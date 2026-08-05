// Thread-local storage on Darwin, which is not a pointer but a call.
//
// A reference to a `_Thread_local` compiles to "load the thunk out of the
// descriptor and call it", and the loader is what fills the thunk in. That makes
// TLS a *loader* feature on macOS rather than a compiler one, and it is the thing
// the stock macOS CPython stopped on -- libsystem_c aborted with "thread locals
// not initialized" before Python printed anything.
//
// Two properties are checked, and they fail differently:
//
//   * the initial value arrives. A thunk that returns a fresh zeroed block every
//     time still passes a "can I write and read it back" test, but not this one.
//   * each thread gets its own. A thunk that returns one shared block passes both
//     of the above and is wrong in the way that matters.
//
// The answer is arithmetic the host can check without running anything.
extern int printf(const char*, ...);
extern int pthread_create(void** thread, const void* attr,
                          void* (*start)(void*), void* arg);
extern int pthread_join(void* thread, void** value);

static _Thread_local long counter = 100;      // __thread_data: an initial value
static _Thread_local long scratch;            // __thread_bss: zero

static long results[4];

static void* worker(void* arg) {
    const long n = (long)arg;
    // If the block were shared, a later thread would see an earlier thread's
    // counter rather than 100, and the sum would come out too large.
    counter += n;
    scratch = counter * 2;
    results[n - 1] = counter + scratch;
    return 0;
}

int main(void) {
    printf("main counter %ld scratch %ld\n", counter, scratch);
    counter += 7;
    void* t[4];
    for (long i = 0; i < 4; ++i)
        if (pthread_create(&t[i], 0, worker, (void*)(i + 1)) != 0) {
            printf("pthread_create failed\n");
            return 1;
        }
    for (int i = 0; i < 4; ++i) pthread_join(t[i], 0);
    long total = 0;
    for (int i = 0; i < 4; ++i) total += results[i];
    // Each worker: counter = 100 + n, scratch = 2*(100+n), sum = 3*(100+n).
    // Over n = 1..4 that is 3*(400+10) = 1230.
    printf("workers %ld (expected 1230)\n", total);
    // And the main thread's own copy is untouched by any of them.
    printf("main after %ld (expected 107)\n", counter);
    return 0;
}
