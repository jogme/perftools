/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <openssl/evp.h>
#include "perflib/perflib.h"

#define NUM_CALLS_PER_TEST         1000000

size_t num_calls;
OSSL_TIME *times;

enum {
    ALGO_X25519,
} algorithm = ALGO_X25519;
const char *alg_name = "X25519";

int err = 0;

static unsigned char key_x25519[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static int threadcount;

void do_newrawkey(size_t num)
{
    size_t i;
    EVP_PKEY *pkey;
    OSSL_TIME start, end;
    const unsigned char *key_data = key_x25519;
    size_t key_len = sizeof(key_x25519);

    switch (algorithm) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
        case ALGO_ML_KEM_512:
            key_data = key_ml_kem512;
            key_len = sizeof(key_ml_kem512);
            break;
        case ALGO_ML_KEM_768:
            key_data = key_ml_kem768;
            key_len = sizeof(key_ml_kem768);
            break;
        case ALGO_ML_KEM_1024:
            key_data = key_ml_kem1024;
            key_len = sizeof(key_ml_kem1024);
            break;
#endif
        /*
         * x25519 is the default algorithm
         */
        default:
            break;
    }

    start = ossl_time_now();

    for (i = 0; i < num_calls / threadcount; i++) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg_name, NULL, key_data,
                                              key_len);
#else
        /*
         * For OpenSSL versions < 3.0, we test only x25519
         */
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key_data,
                                           sizeof(key_data));
#endif
        if (pkey == NULL)
            err = 1;
        else
            EVP_PKEY_free(pkey);
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);
}

int main(int argc, char *argv[])
{
    OSSL_TIME duration;
    OSSL_TIME ttime;
    double av;
    int terse = 0;
    size_t i;
    int rc = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "ta:")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 'a':
            if (strcmp(optarg, "x25519") == 0) {
                algorithm = ALGO_X25519;
                alg_name = "X25519";
            } else {
                printf("Unknown algorithm %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        default:
            printf("Usage: %s [-t] [-a algorithm] threadcount\n", basename(argv[0]));
            printf("-t - terse output\n");
            printf("-a algorithm - specify the algorithm to test (default: x25519)\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("threadcount is missing\n");
        return EXIT_FAILURE;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        return EXIT_FAILURE;
    }
    num_calls = NUM_CALLS_PER_TEST;
    if (NUM_CALLS_PER_TEST % threadcount > 0) /* round up */
        num_calls += threadcount - NUM_CALLS_PER_TEST % threadcount;

    times = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (times == NULL) {
        printf("Failed to create times array\n");
        return EXIT_FAILURE;
    }

    if (!perflib_run_multi_thread_test(do_newrawkey, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto out;
    }

    if (err) {
        printf("Error during test\n");
        goto out;
    }

    ttime = times[0];
    for (i = 1; i < threadcount; i++)
        ttime = ossl_time_add(ttime, times[i]);

    /*
     * EVP_PKEY_new_raw_public_key is pretty fast, running in
     * only a few us.  But ossl_time2us does integer division
     * and so because the average us computed above is less than
     * the value of OSSL_TIME_US, we wind up with truncation to
     * zero in the math.  Instead, manually do the division, casting
     * our values as doubles so that we compute the proper time
     */
    av = ((double)ossl_time2ticks(ttime) / num_calls) /(double)OSSL_TIME_US;

    if (terse)
        printf("%lf\n", av);
    else
        printf("Average time per EVP_PKEY_new_raw_public_key_ex() call for algorithm %s: %lfus\n",
               alg_name, av);

    rc = EXIT_SUCCESS;
out:
    OPENSSL_free(times);
    return rc;
}
