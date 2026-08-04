// A macOS guest that does more than print: four threads, a mutex, and a join.
//
// No headers, on purpose -- there is no Apple SDK on the machines this is built
// on, and a guest that declares what it uses needs none. The types are spelled
// out as the sizes libpthread actually uses on arm64 (pthread_t is a pointer,
// pthread_mutex_t is 64 bytes with an 8-byte-aligned first word).
//
// This is the next thing the Darwin side needs after `hello`, and it is here
// *before* the emulator can run it: creating a thread on Darwin goes through
// `bsdthread_create`, not `clone`, and the emulator implements the Linux one.
// The point of committing it is that the guest is the test -- when
// bsdthread_create lands, this says whether it works, and the answer it prints is
// checkable without knowing anything about the emulator.
extern int printf(const char*, ...);
extern int pthread_create(void** thread, const void* attr,
                          void* (*start)(void*), void* arg);
extern int pthread_join(void* thread, void** value);
extern int pthread_mutex_lock(void* m);
extern int pthread_mutex_unlock(void* m);

// PTHREAD_MUTEX_INITIALIZER: the signature word 0x32AAABA7 followed by zeroes.
static struct { long sig; char opaque[56]; } mutex = { 0x32AAABA7L, {0} };

static long total;

static void* worker(void* arg) {
    const long n = (long)arg;
    long sum = 0;
    for (long i = 1; i <= n; ++i) sum += i;
    pthread_mutex_lock(&mutex);
    total += sum;
    pthread_mutex_unlock(&mutex);
    return 0;
}

int main(void) {
    void* t[4];
    for (long i = 0; i < 4; ++i)
        if (pthread_create(&t[i], 0, worker, (void*)((i + 1) * 1000)) != 0) {
            printf("pthread_create failed\n");
            return 1;
        }
    for (int i = 0; i < 4; ++i) pthread_join(t[i], 0);
    // 500500 + 2001000 + 4501500 + 8002000, which the host can check without
    // running anything.
    printf("total %ld (expected 15005000)\n", total);
    return total == 15005000 ? 0 : 1;
}
