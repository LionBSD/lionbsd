/*
 * Copyright (c) 2016 The LionBSD Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Based on:
 * Argon2 reference implementation. Released into the Public Domain by
 * Daniel Dinu and Dmitry Khovratovich, 2015
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#define _GNU_SOURCE 1

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2/argon2.h"
#include "argon2/core.h"

#define T_COST_DEF 10
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUTLEN_DEF 32
#define MAX_PASS_LEN 128

#define UNUSED_PARAMETER(x) (void)(x)

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
}

/*
@pwd NULL-terminated string
@salt salt array
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
*/

char *
crypt_argon2i_r(uint32_t outlen, const char *pwd, const char *salt, uint32_t t_cost,
                uint32_t m_cost, uint32_t lanes, uint32_t threads)
{
    size_t pwdlen, saltlen, encodedlen;
    int result;

    if (!pwd) {
        fatal("password missing");
	return NULL;
    }

    if (!salt) {
        //secure_wipe_memory(pwd, strlen(pwd));
        fatal("salt missing");
	return NULL;
    }

    pwdlen = strlen(pwd);
    saltlen = strlen(salt);

    UNUSED_PARAMETER(lanes);

    encodedlen = argon2_encodedlen(t_cost, m_cost, lanes, saltlen, outlen);
    char* encoded = malloc(encodedlen + 1);
    if (!encoded) {
        //secure_wipe_memory(pwd, strlen(pwd));
        fatal("could not allocate memory for hash");
	return NULL;
    }

    result = argon2i_hash_encoded(t_cost, m_cost, threads, pwd, pwdlen, salt, saltlen,
                         outlen, encoded, encodedlen);

    if (result != ARGON2_OK) {
        fatal(argon2_error_message(result));
	return NULL;
    }

    result = argon2i_verify(encoded, pwd, pwdlen);
    if (result != ARGON2_OK) {
        fatal(argon2_error_message(result));
	return NULL;
    }

    /* FIXME: make encoded a static char* */
    // free(encoded);
    return encoded;
}

/*
 * We handle $argon2i[$v=<num>]$m=<num>,t=<num>,p=<num>[,keyid=<bin>][,data=<bin>][$<bin>[$<bin>]]
 *
 * where <bin> is Base64-encoded data (no '=' padding * characters,
 * no newline or whitespace).
 * The "keyid" is a binary identifier for a key (up to 8 bytes);
 * "data" is associated data (up to 32 bytes). When the 'keyid'
 * (resp. the 'data') is empty, then it is ommitted from the output.
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are optional, but you cannot have an
 * output without a salt. The binary salt length is between 8 and 48 bytes.
 * The output length is always exactly 32 bytes.
 *
 * Example: $argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE
 */

char *
crypt_argon2i(const char *key, const char *salt)
{
    uint32_t outlen = OUTLEN_DEF;
    uint32_t m_cost = 1 << LOG_M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;
    int result = 0;
    size_t pwdlen = 0;
    //static char* buffer;
    //static int buflen;

    if (*salt == '$') {
        pwdlen = strlen(key);
        result = argon2i_verify(salt, key, pwdlen);
        if (result != ARGON2_OK) {
            return NULL;
        }

        // FIXME: don't leak memory
        return strdup(salt);
    }
    else {
        return crypt_argon2i_r(outlen, key, salt, t_cost, m_cost, lanes, threads);
    }
}
