extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
}
#include "hls_stream.h"
#define MAX_UPDATE 256
#define MAX_PASSW 16
#define MAX_SALT 16
#define GROUP_LENGTH 256
#define lp 6
#define ls 8
//ab7d8f6c34c4d7a96179920718a1ee66076f862b9392260fc555e849601440408600a9babe702a6f8dfd159da517a1337145c24b372cae59d9cb080c3630d75c
//#define FIXED_SIX
//#define NO_FUNC_COPY
//#define OP_WPC
//#define HASHCAT


int compare_digest_sha512 (const void *p1, const void *p2);
uint64_t ROTR( int n, uint64_t x) ;
uint64_t SHR( int n, uint64_t x) ;
uint64_t choose (uint64_t x, uint64_t y, uint64_t z) ;
uint64_t majority (uint64_t x, uint64_t y, uint64_t z) ;
uint64_t SIGMA0(uint64_t x) ;
uint64_t SIGMA1(uint64_t x) ;
uint64_t sig0(uint64_t x);
uint64_t sig1(uint64_t x);
uint64_t addv(uint64_t x, uint64_t y);
void david_hash(uint64_t wordblock[16],uint8_t digest[64]);
void transmit(uint64_t *input, unsigned char *output);
#define BYTESWAP64(x) x = \
   ((((x) & 0xff00000000000000ull) >> 56)   \
  | (((x) & 0x00ff000000000000ull) >> 40)   \
  | (((x) & 0x0000ff0000000000ull) >> 24)   \
  | (((x) & 0x000000ff00000000ull) >>  8)   \
  | (((x) & 0x00000000ff000000ull) <<  8)   \
  | (((x) & 0x0000000000ff0000ull) << 24)   \
  | (((x) & 0x000000000000ff00ull) << 40)   \
  | (((x) & 0x00000000000000ffull) << 56))


#define PUTCHAR64_BE(a,p,c) ((uint8_t *)(a))[(p) ^ 7] = (uint8_t) (c)
#define GETCHAR64_BE(a,p) ((uint8_t *)(a))[(p) ^ 7]

#define LOAD64H( x, y )                                                      \
   { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
         (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
         (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
         (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

#define STORE64H( x, y )                                                                     \
   { (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
     (y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
     (y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
     (y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }


#define PUT64BE( x, y )                                                      \
   { x = (((uint64_t)((y)[0] & 255)))|(((uint64_t)((y)[1] & 255))<<8) | \
         (((uint64_t)((y)[2] & 255))<<16)|(((uint64_t)((y)[3] & 255))<<24) | \
         (((uint64_t)((y)[4] & 255))<<32)|(((uint64_t)((y)[5] & 255))<<40) | \
         (((uint64_t)((y)[6] & 255))<<48)|(((uint64_t)((y)[7] & 255))<<56); }

typedef struct
{

	uint8_t  passwd[MAX_PASSW];

}pwd_t;

typedef struct
{

	uint8_t  salt[MAX_SALT];

} salt_t;

typedef struct
{

	uint64_t  buf64[8];

} digest_t;

typedef struct
{
  union{
	//  uint8_t stp[64];
	  uint64_t state[8];

  };

  union
  {
    uint64_t w[16];
    uint8_t  buf[128];
  };

 // int len;

} loop_sha512_ctx;

typedef struct
{
  union{
	//  uint8_t stp[64];
	  uint64_t state[8];

  };

  union
  {
    uint64_t w[16];
    uint8_t  buf[128];
  };

  int len;

} hc_sha512_ctx;

typedef struct
{
    union{
    	uint64_t buf64[8];
    	uint8_t buf8[64];
    };
  uint32_t len;
} plain_t;


void sha512_init(hc_sha512_ctx *ctx) ;
void hashcat_sha512(uint64_t digest[8], uint64_t wordblock[16]);
void no_hashcat_sha512(uint64_t digest[8], uint64_t wordblock[16]);
void sha512_update(hc_sha512_ctx *ctx, unsigned char *buf, int len) ;
void init0_six_final(hc_sha512_ctx *ctx) ;
void sha512_final(hc_sha512_ctx *ctx) ;
void loop_sha512_final_2(hc_sha512_ctx *ctx);
void loop_sha512_final(uint64_t *state, uint64_t *words);


#define SHA512M_A 0x6a09e667f3bcc908ull
#define SHA512M_B 0xbb67ae8584caa73bull
#define SHA512M_C 0x3c6ef372fe94f82bull
#define SHA512M_D 0xa54ff53a5f1d36f1ull
#define SHA512M_E 0x510e527fade682d1ull
#define SHA512M_F 0x9b05688c2b3e6c1full
#define SHA512M_G 0x1f83d9abfb41bd6bull
#define SHA512M_H 0x5be0cd19137e2179ull

static const uint64_t INIT_STATE[8] ={ SHA512M_A, SHA512M_B,SHA512M_C, SHA512M_D,SHA512M_E,SHA512M_F, SHA512M_G,SHA512M_H};

#define DIGEST_SIZE_SHA512         8 * 8

static const uint64_t K[80] = {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
	0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL,
	0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL,
	0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL,
	0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL,
	0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
	0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL,
	0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL,
	0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL,
	0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
	0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
	0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL,
	0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL,
	0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};



#define ROR64( value, bits ) (((value) >> (bits)) | ((value) << (64 - (bits))))

#define MIN( x, y ) ( ((x)<(y))?(x):(y) )

#define Ch( x, y, z )     (z ^ (x & (y ^ z)))
#define Maj(x, y, z )     (((x | y) & z) | (x & y))
#define S( x, n )         ROR64( x, n )
#define R( x, n )         (((x)&0xFFFFFFFFFFFFFFFFULL)>>((uint64_t)n))
#define Sigma0( x )       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1( x )       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0( x )       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1( x )       (S(x, 19) ^ S(x, 61) ^ R(x, 6))

#define Sha512Round( a, b, c, d, e, f, g, h, i )       \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                    \
     d += t0;                                          \
     h = t0 + t1;

#define LOAD64H( x, y )                                                      \
   { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
         (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
         (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
         (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

#define STORE64HB( x, y )                                                                     \
   { (y)[0] = (((x)>>56)&255); (y)[1] = (((x)>>48)&255);     \
     (y)[2] = (((x)>>40)&255); (y)[3] = (((x)>>32)&255);     \
     (y)[4] = (((x)>>24)&255); (y)[5] = (((x)>>16)&255);     \
     (y)[6] =(((x)>>8)&255); (y)[7] = ((x)&255); }


#define STORE64H( x, y )                                                                     \
   { (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
     (y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
     (y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
     (y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }

