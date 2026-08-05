// Child processes: fork, execve, wait4.
//
// **These are vfork semantics, deliberately.** The parent is suspended the moment it
// forks and does not run again until the child execs or exits; the two never run at
// the same time. The child runs in the parent's own address space until `execve`, at
// which point the new program gets a fresh one -- which is exactly what `vfork(2)`
// promises and exactly what the code that matters here does with it:
//
//     pid = fork();
//     if (pid == 0) { dup2(fd, 1); close(fd); execve(...); _exit(127); }
//     waitpid(pid, &status, 0);
//
// gcc's driver spawns cc1, as and ld that way; make spawns gcc that way; Python's
// `subprocess` spawns everything that way. Between the fork and the exec a child is
// only allowed to touch descriptors, and descriptors are shared here anyway.
//
// What this does *not* support, and would report rather than fake:
//
//   * a child that runs concurrently with its parent. A pipeline where the writer
//     must be scheduled while the reader blocks cannot work; the pipe buffer is
//     unbounded so the common shape (child writes, exits, parent reads) does, and
//     `Files::Pipe` says why.
//   * a child that returns from `fork()` and keeps going without exec'ing. That is
//     genuine fork, needs a second address space, and is the next piece of work.
//
// The recursion is real: a vfork child may fork again, which is why the saved
// contexts are a stack rather than one slot. `make -j1` running `gcc` running `cc1`
// is three levels.
#include "syscalls.h"
#include <cstdio>

namespace a64 {

namespace {
// Read a NULL-terminated array of C strings out of guest memory: argv and envp both
// arrive that way. A cap, because a wild pointer here would otherwise walk memory
// until it faulted rather than saying what was wrong.
std::vector<std::string> read_strv(Memory& mem, uint64_t addr, size_t cap = 4096) {
    std::vector<std::string> v;
    if (!addr) return v;
    for (size_t i = 0; i < cap; ++i) {
        const uint64_t p = mem.read<uint64_t>(addr + i * 8);
        if (!p) break;
        v.push_back(mem.read_cstr(p));
    }
    return v;
}
}  // namespace

// fork(): the parent's registers and its descriptor table go on a stack, and the
// child continues in place seeing 0 in x0. The *memory* is not copied -- the child is
// in the parent's until it execs, which is what makes this vfork rather than fork --
// but the descriptor table is, and has to be. See the note on `vfork_files_`.
int64_t Syscalls::sys_fork() {
    vfork_saved_.push_back(cpu_.save_context());
    vfork_files_.push_back(files);
    ++vfork_depth_;
    const int pid = next_pid_++;
    vfork_child_pid_ = pid;
    if (trace)
        std::fprintf(stderr, "[proc] fork -> child pid %d (depth %d) parent pc %llX sp %llX\n",
                     pid, vfork_depth_, static_cast<unsigned long long>(cpu_.pc),
                     static_cast<unsigned long long>(cpu_.sp));
    return 0;                                   // the child's view
}

// execve(): load and run the named program to completion, then hand its status back
// to the parent and resume the parent.
//
// "To completion" is the compromise this whole file is built around, and it is worth
// being clear that it *is* one: a real execve replaces the calling image and returns
// to nobody. Here the caller is a vfork child whose only remaining job is to become
// the new program, so running that program and then resuming the parent produces the
// same observable sequence -- as long as the parent was going to wait, which after a
// vfork it must.
int64_t Syscalls::sys_execve(uint64_t path_addr, uint64_t argv_addr, uint64_t envp_addr) {
    const std::string path = guest_str(path_addr);
    std::vector<std::string> argv = read_strv(mem_, argv_addr);
    const std::vector<std::string> envp = read_strv(mem_, envp_addr);
    if (argv.empty()) argv.push_back(path);

    if (!spawn) {
        std::fprintf(stderr, "[proc] execve(%s) but this front end cannot spawn\n",
                     path.c_str());
        return -38;                             // ENOSYS
    }
    if (!in_vfork_child()) {
        // exec without a fork: the guest means to *replace* itself, and there is no
        // parent to come back to. Running the new program and then stopping is the
        // closest honest thing, and it is what a shell's `exec cmd` wants.
        const int st = spawn(path, argv, envp, files);
        cpu_.exit_code = st < 0 ? 127 : st;
        cpu_.halted = true;
        return 0;
    }
    if (trace)
        std::fprintf(stderr, "[proc] execve %s (%zu args)\n", path.c_str(), argv.size());
    const int st = spawn(path, argv, envp, files);
    // A program that could not be started is `_exit(127)`, which is what a shell
    // reports and what `subprocess` turns into FileNotFoundError once it sees the
    // status. Reporting ENOENT to the *child* would be wrong: the child is gone.
    vfork_child_status_ = (st < 0 ? 127 : st) << 8;
    vfork_returning_ = true;
    // Set here rather than in the shared syscall tail: `execve` returns early from
    // the dispatcher (it has no return value to write), so it never reaches the tail
    // -- and a child that is not stopped runs on into the bytes of its own argv.
    cpu_.stop_requested = true;
    return 0;
}

// Called by the run loop when a vfork child has finished: put the parent back and
// make its `fork()` return the child's pid.
void Syscalls::vfork_resume() {
    if (!vfork_returning_) return;
    vfork_returning_ = false;
    --vfork_depth_;
    cpu_.load_context(vfork_saved_.back());
    vfork_saved_.pop_back();
    files = vfork_files_.back();
    vfork_files_.pop_back();
    child_status_[vfork_child_pid_] = vfork_child_status_;
    cpu_.setx(0, static_cast<uint64_t>(vfork_child_pid_));
    if (trace)
        std::fprintf(stderr, "[proc] child %d exited %d; parent resumes at pc %llX sp %llX\n",
                     vfork_child_pid_, vfork_child_status_ >> 8,
                     static_cast<unsigned long long>(cpu_.pc),
                     static_cast<unsigned long long>(cpu_.sp));
}

// wait4(): the child has already run, so its status is on hand. Anything else --
// waiting for a pid that was never forked here -- is ECHILD.
int64_t Syscalls::sys_wait4(int64_t pid, uint64_t status_addr) {
    auto it = pid < 0 ? child_status_.begin() : child_status_.find(static_cast<int>(pid));
    if (it == child_status_.end()) return -10;  // ECHILD
    const int st = it->second;
    const int got = it->first;
    child_status_.erase(it);
    if (status_addr) mem_.write<uint32_t>(status_addr, static_cast<uint32_t>(st));
    return got;
}

}  // namespace a64
