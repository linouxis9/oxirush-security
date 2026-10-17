/*
 * The MILENAGE and the NAS security of Open5GS, as compare.sh runs them,
 * built from Open5GS's source tree:
 *
 *   open5gs-security <case> <iterations>
 *
 * The cases are those of the Rust program: av, an authentication vector of
 * MILENAGE (milenage_generate), and nea1 to nia3, the ciphering or the MAC of
 * a message of 1500 octets (ogs_nas_encrypt and ogs_nas_mac_calculate, which
 * the AMF and the MME of Open5GS call, on a packet buffer made once). It
 * prints the nanoseconds, the allocations and the octets allocated per
 * operation, and the peak memory of the program in KiB.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#include "ogs-nas-common.h"

/* The allocator of the program, which counts the allocations of every
 * library and their octets, and gives them to that of the C library. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
static unsigned long long allocations, allocated;

void *malloc(size_t size)
{
    allocations++;
    allocated += size;
    return __libc_malloc(size);
}

void *calloc(size_t count, size_t size)
{
    allocations++;
    allocated += count * size;
    return __libc_calloc(count, size);
}

void *realloc(void *pointer, size_t size)
{
    allocations++;
    allocated += size;
    return __libc_realloc(pointer, size);
}

void free(void *pointer)
{
    __libc_free(pointer);
}

/* The inputs of the Rust program. */
static uint8_t key[16] = {0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c,
                          0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8, 0xc6, 0xd1};
static const uint32_t count = 0x398a59b4;
static const uint8_t bearer = 0x15, direction = 1;
static const uint8_t opc[16] = {0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
                                0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf};
static const uint8_t k[16] = {0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
                              0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc};
static const uint8_t rand_[16] = {0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d,
                                  0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35};
static const uint8_t sqn[6] = {0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07};
static const uint8_t amf[2] = {0xb9, 0xb9};
#define LENGTH 1500

static ogs_pkbuf_t *pkbuf;
static uint8_t mac[4];

static void av(void)
{
    uint8_t autn[16], ik[16], ck[16], ak[6], res[8];
    size_t res_length = sizeof res;
    milenage_generate(opc, amf, k, sqn, rand_, autn, ik, ck, ak, res, &res_length);
}

static void nea1(void) { ogs_nas_encrypt(OGS_NAS_SECURITY_ALGORITHMS_128_EEA1, key, count, bearer, direction, pkbuf); }
static void nea2(void) { ogs_nas_encrypt(OGS_NAS_SECURITY_ALGORITHMS_128_EEA2, key, count, bearer, direction, pkbuf); }
static void nea3(void) { ogs_nas_encrypt(OGS_NAS_SECURITY_ALGORITHMS_128_EEA3, key, count, bearer, direction, pkbuf); }
static void nia1(void) { ogs_nas_mac_calculate(OGS_NAS_SECURITY_ALGORITHMS_128_EIA1, key, count, bearer, direction, pkbuf, mac); }
static void nia2(void) { ogs_nas_mac_calculate(OGS_NAS_SECURITY_ALGORITHMS_128_EIA2, key, count, bearer, direction, pkbuf, mac); }
static void nia3(void) { ogs_nas_mac_calculate(OGS_NAS_SECURITY_ALGORITHMS_128_EIA3, key, count, bearer, direction, pkbuf, mac); }

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        {"av", av}, {"nea1", nea1}, {"nea2", nea2}, {"nea3", nea3},
        {"nia1", nia1}, {"nia2", nia2}, {"nia3", nia3},
    };
    ogs_pkbuf_config_t config;
    void (*run)(void) = NULL;
    unsigned long long allocations_before, allocated_before;
    long iterations, i;
    double start, elapsed;
    struct rusage usage;
    uint8_t data[LENGTH];

    if (argc != 3) {
        fprintf(stderr, "open5gs-security <case> <iterations>\n");
        return 2;
    }
    for (i = 0; i < (long)(sizeof cases / sizeof cases[0]); i++)
        if (!strcmp(argv[1], cases[i].name))
            run = cases[i].run;
    if (!run) {
        fprintf(stderr, "no case %s\n", argv[1]);
        return 2;
    }
    iterations = atol(argv[2]);
    ogs_core_initialize();
    ogs_pkbuf_default_init(&config);
    ogs_pkbuf_default_create(&config);
    memset(data, 0x5a, sizeof data);
    /* Room before the message, where the MAC of 128-EIA2 puts its header */
    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_reserve(pkbuf, 16);
    ogs_pkbuf_put_data(pkbuf, data, sizeof data);

    run();
    allocations_before = allocations;
    allocated_before = allocated;
    start = now();
    for (i = 0; i < iterations; i++)
        run();
    elapsed = now() - start;
    getrusage(RUSAGE_SELF, &usage);
    printf("%.1f %.2f %.0f %ld\n", elapsed / iterations,
           (double)(allocations - allocations_before) / iterations,
           (double)(allocated - allocated_before) / iterations, usage.ru_maxrss);
    return 0;
}
