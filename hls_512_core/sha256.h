#ifndef _CIPHER_SHA512_H
#define _CIPHER_SHA512_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */
#include<stdint.h>
#define MAXLEN 1024
//#define MY_DEBUG
//#define NEW_COM
//#define LOOKUP
#define NEW_COM
#define ROUND_FUN

#ifndef NEW_COM
#define chartonumber(x) (x-'0')
#define add(r,x,y) ( r.lo = y.lo + x.lo, \
                     r.hi = y.hi + x.hi + ((uint32)r.lo < (uint32)y.lo) )
#define rorB(r,x,y) ( r.lo = ((uint32)x.hi >> ((y)-32)) | ((uint32)x.lo << (64-(y))), \
                      r.hi = ((uint32)x.lo >> ((y)-32)) | ((uint32)x.hi << (64-(y))) )
#define rorL(r,x,y) ( r.lo = ((uint32)x.lo >> (y)) | ((uint32)x.hi << (32-(y))), \
                      r.hi = ((uint32)x.hi >> (y)) | ((uint32)x.lo << (32-(y))) )
#define shrB(r,x,y) ( r.lo = (uint32)x.hi >> ((y)-32), r.hi = 0 )
#define shrL(r,x,y) ( r.lo = ((uint32)x.lo >> (y)) | ((uint32)x.hi << (32-(y))), \
                      r.hi = (uint32)x.hi >> (y) )
#define and(r,x,y) ( r.lo = x.lo & y.lo, r.hi = x.hi & y.hi )
#define xor(r,x,y) ( r.lo = x.lo ^ y.lo, r.hi = x.hi ^ y.hi )
#define not(r,x) ( r.lo = ~x.lo, r.hi = ~x.hi )
#define INIT(h,l) { h, l }
#define BUILD(r,h,l) ( r.hi = h, r.lo = l )
#define EXTRACT(h,l,r) ( h = r.hi, l = r.lo )


#define Ch(r,t,x,y,z) ( not(t,x), and(r,t,z), and(t,x,y), xor(r,r,t) )
#define Maj(r,t,x,y,z) ( and(r,x,y), and(t,x,z), xor(r,r,t), \
                         and(t,y,z), xor(r,r,t) )
#define bigsigma0(r,t,x) ( rorL(r,x,28), rorB(t,x,34), xor(r,r,t), \
                           rorB(t,x,39), xor(r,r,t) )
#define bigsigma1(r,t,x) ( rorL(r,x,14), rorL(t,x,18), xor(r,r,t), \
                           rorB(t,x,41), xor(r,r,t) )
#define smallsigma0(r,t,x) ( rorL(r,x,1), rorL(t,x,8), xor(r,r,t), \
                             shrL(t,x,7), xor(r,r,t) )
#define smallsigma1(r,t,x) ( rorL(r,x,19), rorB(t,x,61), xor(r,r,t), \
                             shrL(t,x,6), xor(r,r,t) )

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value))
#endif
#ifdef NEW_COM
#define SHA512_HASH_SIZE ( 512 / 8 )
typedef struct
{
    uint8_t   bytes [SHA512_HASH_SIZE];
}SHA512_HASH;

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
   { x = (((uint64_t)((y) & 255))<<56)|(((uint64_t)((y) & 255))<<48) | \
         (((uint64_t)((y) & 255))<<40)|(((uint64_t)((y) & 255))<<32) | \
         (((uint64_t)((y) & 255))<<24)|(((uint64_t)((y) & 255))<<16) | \
         (((uint64_t)((y) & 255))<<8)|(((uint64_t)((y) & 255))); }

/*#define LOAD64H( x, y )                                                      \
   { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
         (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
         (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
         (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }*/

#define STORE64H( x, y )                                                                     \
   { (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
     (y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
     (y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
     (y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }
#endif
typedef struct {
    unsigned long hi, lo;
} uint64;
typedef unsigned int uint32;
typedef struct {
    uint64 h[8];
    unsigned char block[128];
    int blkused;
    uint32 len[4];
} SHA512_State;

typedef struct {
	unsigned char passwd[32];
	//unsigned char len;
} p_in;

typedef struct {
	unsigned char digest[64];
} d_out;
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


#ifndef NEW_COM
static const uint64 k[] = {
    INIT(0x428a2f98, 0xd728ae22), INIT(0x71374491, 0x23ef65cd),
    INIT(0xb5c0fbcf, 0xec4d3b2f), INIT(0xe9b5dba5, 0x8189dbbc),
    INIT(0x3956c25b, 0xf348b538), INIT(0x59f111f1, 0xb605d019),
    INIT(0x923f82a4, 0xaf194f9b), INIT(0xab1c5ed5, 0xda6d8118),
    INIT(0xd807aa98, 0xa3030242), INIT(0x12835b01, 0x45706fbe),
    INIT(0x243185be, 0x4ee4b28c), INIT(0x550c7dc3, 0xd5ffb4e2),
    INIT(0x72be5d74, 0xf27b896f), INIT(0x80deb1fe, 0x3b1696b1),
    INIT(0x9bdc06a7, 0x25c71235), INIT(0xc19bf174, 0xcf692694),
    INIT(0xe49b69c1, 0x9ef14ad2), INIT(0xefbe4786, 0x384f25e3),
    INIT(0x0fc19dc6, 0x8b8cd5b5), INIT(0x240ca1cc, 0x77ac9c65),
    INIT(0x2de92c6f, 0x592b0275), INIT(0x4a7484aa, 0x6ea6e483),
    INIT(0x5cb0a9dc, 0xbd41fbd4), INIT(0x76f988da, 0x831153b5),
    INIT(0x983e5152, 0xee66dfab), INIT(0xa831c66d, 0x2db43210),
    INIT(0xb00327c8, 0x98fb213f), INIT(0xbf597fc7, 0xbeef0ee4),
    INIT(0xc6e00bf3, 0x3da88fc2), INIT(0xd5a79147, 0x930aa725),
    INIT(0x06ca6351, 0xe003826f), INIT(0x14292967, 0x0a0e6e70),
    INIT(0x27b70a85, 0x46d22ffc), INIT(0x2e1b2138, 0x5c26c926),
    INIT(0x4d2c6dfc, 0x5ac42aed), INIT(0x53380d13, 0x9d95b3df),
    INIT(0x650a7354, 0x8baf63de), INIT(0x766a0abb, 0x3c77b2a8),
    INIT(0x81c2c92e, 0x47edaee6), INIT(0x92722c85, 0x1482353b),
    INIT(0xa2bfe8a1, 0x4cf10364), INIT(0xa81a664b, 0xbc423001),
    INIT(0xc24b8b70, 0xd0f89791), INIT(0xc76c51a3, 0x0654be30),
    INIT(0xd192e819, 0xd6ef5218), INIT(0xd6990624, 0x5565a910),
    INIT(0xf40e3585, 0x5771202a), INIT(0x106aa070, 0x32bbd1b8),
    INIT(0x19a4c116, 0xb8d2d0c8), INIT(0x1e376c08, 0x5141ab53),
    INIT(0x2748774c, 0xdf8eeb99), INIT(0x34b0bcb5, 0xe19b48a8),
    INIT(0x391c0cb3, 0xc5c95a63), INIT(0x4ed8aa4a, 0xe3418acb),
    INIT(0x5b9cca4f, 0x7763e373), INIT(0x682e6ff3, 0xd6b2b8a3),
    INIT(0x748f82ee, 0x5defb2fc), INIT(0x78a5636f, 0x43172f60),
    INIT(0x84c87814, 0xa1f0ab72), INIT(0x8cc70208, 0x1a6439ec),
    INIT(0x90befffa, 0x23631e28), INIT(0xa4506ceb, 0xde82bde9),
    INIT(0xbef9a3f7, 0xb2c67915), INIT(0xc67178f2, 0xe372532b),
    INIT(0xca273ece, 0xea26619c), INIT(0xd186b8c7, 0x21c0c207),
    INIT(0xeada7dd6, 0xcde0eb1e), INIT(0xf57d4f7f, 0xee6ed178),
    INIT(0x06f067aa, 0x72176fba), INIT(0x0a637dc5, 0xa2c898a6),
    INIT(0x113f9804, 0xbef90dae), INIT(0x1b710b35, 0x131c471b),
    INIT(0x28db77f5, 0x23047d84), INIT(0x32caab7b, 0x40c72493),
    INIT(0x3c9ebe0a, 0x15c9bebc), INIT(0x431d67c4, 0x9c100d4c),
    INIT(0x4cc5d4be, 0xcb3e42b6), INIT(0x597f299c, 0xfc657e2a),
    INIT(0x5fcb6fab, 0x3ad6faec), INIT(0x6c44198c, 0x4a475817),
};
static const uint64 iv[] = {
    INIT(0x6a09e667, 0xf3bcc908),
    INIT(0xbb67ae85, 0x84caa73b),
    INIT(0x3c6ef372, 0xfe94f82b),
    INIT(0xa54ff53a, 0x5f1d36f1),
    INIT(0x510e527f, 0xade682d1),
    INIT(0x9b05688c, 0x2b3e6c1f),
    INIT(0x1f83d9ab, 0xfb41bd6b),
    INIT(0x5be0cd19, 0x137e2179),
};


#define ROUND(j,a,b,c,d,e,f,g,h) \
        bigsigma1(p, tmp, e); \
        Ch(q, tmp, e, f, g); \
        add(r, p, q); \
        add(p, r, k[j]) ; \
        add(q, p, w[j]); \
        add(r, q, h); \
        bigsigma0(p, tmp, a); \
        Maj(tmp, q, a, b, c); \
        add(q, tmp, p); \
        add(p, r, d); \
        d = p; \
        add(h, q, r);

#define UPDATE(state, local) ( tmp = state, add(state, tmp, local) )

#endif


    void SHA512_Init(SHA512_State * s);
    void SHA512_Bytes(SHA512_State * s, const void *p, int len);
    void SHA512_Final(SHA512_State * s, unsigned char *output);
    //void SHA512_Simple(unsigned char p[MAXLEN], int len, unsigned char *output);
   void SHA512_Simple(p_in *p, unsigned char len, d_out *digest);
    //void SHA512_Simple(p_in *p, unsigned char digest[512]);
#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_SHA512_H */
