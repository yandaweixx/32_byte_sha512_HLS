/**
 * \file sha256.h
 *
 * \brief SHA-224 and SHA-256 cryptographic hash function
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H
/***
#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
***/

extern "C"{
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
}
#include "hls_stream.h"

#define N 106
#define NN 212
#define NUM3 256
#define MAX_PASSW 64

typedef unsigned int uint32_t;
typedef unsigned short int uint16_t;


typedef struct
{
	uint32_t  pwd[MAX_PASSW/4];
}pwd_t;

typedef struct
{
	uint32_t  salt_buf[4];
}salt_t;

typedef struct
{
	uint32_t  digest[2];
}digest_t;



void top_rar5(hls::stream<pwd_t> &pwd, hls::stream<salt_t> &salt_buf, hls::stream<digest_t> &digest);


#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
do {                                                    \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
do {                                                    \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
} while( 0 )
#endif





//***#if !defined(MBEDTLS_SHA256_PROCESS_ALT)
static const uint32_t K[] =
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

static const uint32_t INT[] =
{
	0x80000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x00000300
};

static const uint32_t INT1[] =
{
	0x00000001, 0x80000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x000002A0
};

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}



static const char SIGNATURE_RAR5[]            = "$rar5$";
#define DISPLAY_LEN_MIN_13000  1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16
#define DISPLAY_LEN_MAX_13000  1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

typedef unsigned char   u8x;
typedef unsigned short  u16x;
typedef unsigned int    u32x;
typedef unsigned long   u64x;

typedef enum parser_rc
{
  PARSER_OK                  = 0,
  PARSER_COMMENT             = -1,
  PARSER_GLOBAL_ZERO         = -2,
  PARSER_GLOBAL_LENGTH       = -3,
  PARSER_HASH_LENGTH         = -4,
  PARSER_HASH_VALUE          = -5,
  PARSER_SALT_LENGTH         = -6,
  PARSER_SALT_VALUE          = -7,
  PARSER_SALT_ITERATION      = -8,
  PARSER_SEPARATOR_UNMATCHED = -9,
  PARSER_SIGNATURE_UNMATCHED = -10,
  PARSER_HCCAP_FILE_SIZE     = -11,
  PARSER_HCCAP_EAPOL_SIZE    = -12,
  PARSER_PSAFE2_FILE_SIZE    = -13,
  PARSER_PSAFE3_FILE_SIZE    = -14,
  PARSER_TC_FILE_SIZE        = -15,
  PARSER_VC_FILE_SIZE        = -16,
  PARSER_SIP_AUTH_DIRECTIVE  = -17,
  PARSER_HASH_FILE           = -18,
  PARSER_UNKNOWN_ERROR       = -255

} parser_rc_t;

void sha256_process_ini( uint32_t state[8], const uint32_t data[16], uint32_t ret[8]);
//***#if !defined(MBEDTLS_SHA256_ALT)
// Regular implementation
//
/***
#ifdef __cplusplus
extern "C" {
#endif
***/
/**
 * \brief          SHA-256 context structure
 */
//typedef struct
//{
//    uint32_t total[2];          /*!< number of bytes processed  */
//    uint32_t state[8];          /*!< intermediate digest state  */
//    unsigned char buffer[64];   /*!< data block being processed */
//    int is224;                  /*!< 0 => SHA-256, else SHA-224 */
//}


//mbedtls_sha256_context;


#endif /* mbedtls_sha256.h */
