/* test_common.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/wp_logging.h>

/* Test result codes */
#define TEST_SUCCESS    0
#define TEST_FAILURE    1

/* Debug printing macros */
#define TEST_INFO(fmt, ...)    printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define TEST_ERROR(fmt, ...)   fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define TEST_DEBUG(fmt, ...)   do { \
    if (getenv("TEST_DEBUG")) { \
        printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } \
} while(0)

/* Buffer printing for debugging */
#ifdef WOLFPROV_DEBUG
#define TEST_PRINT_BUFFER(desc, buf, len) test_print_buffer(desc, buf, len)
static inline void test_print_buffer(const char *desc, const unsigned char *buffer, size_t len)
{
    size_t i;
    printf("[BUFFER] %s (%zu bytes):\n", desc, len);
    for (i = 0; i < len; i++) {
        printf("%02x ", buffer[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    if ((i % 16) != 0) {
        printf("\n");
    }
    printf("\n");
}
#else
#define TEST_PRINT_BUFFER(desc, buf, len)
#endif

/* Utility functions */
static inline int test_bytes_to_hex(const unsigned char *bytes, size_t len, char *hex, size_t hex_size)
{
    size_t i;
    
    if (hex_size < (len * 2 + 1)) {
        TEST_ERROR("Hex buffer too small");
        return TEST_FAILURE;
    }
    
    for (i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    
    return TEST_SUCCESS;
}

#endif /* TEST_COMMON_H */
