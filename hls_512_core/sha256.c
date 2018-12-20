/*
 * SHA-512 algorithm as described at
 *
 *   http://csrc.nist.gov/cryptval/shs.html
 */
#include <string.h>
#include <stdint.h>
#include "sha256.h"
//#define TEST
#define BLKSIZE 128

/*uint64_t ROR64(uint64_t value, int bits){
 #pragma HLS RESOURCE variable=return core=DSP_Macro
 return  (((value) >> (bits)) | ((value) << (64 - (bits))));
 }*/

/*uint64_t Ch(uint64_t x, uint64_t y, uint64_t z){
 return (z ^ (x & (y ^ z)));
 }*/

#ifdef ROUND_FUN
uint64_t ROTR( int n, uint64_t x) {
	return ((x >> n)) | ((x) << (64 -n));
}
uint64_t SHR( int n, uint64_t x) {
	return ((x >> n));
}
uint64_t choose (uint64_t x, uint64_t y, uint64_t z) {
	return (((x&y)^((~x)&z)));
}
uint64_t majority (uint64_t x, uint64_t y, uint64_t z) {
	return (((x&y)^(x&z)^(y&z)));
}
uint64_t SIGMA0(uint64_t x) {
	return ((ROTR(28, x)^ROTR(34, x)^ROTR(39,x)));
}
uint64_t SIGMA1(uint64_t x) {
	return ((ROTR(14, x)^ROTR(18, x)^ROTR(41,x)));
}
uint64_t sig0(uint64_t x) {
	return ((ROTR(1, x)^ROTR(8, x)^SHR(7,x)));
}
uint64_t sig1(uint64_t x) {
	return ((ROTR(19, x)^ROTR(61, x)^SHR(6,x)));
}

uint64_t addv32(uint64_t x, uint64_t y){
	uint32_t xh, xl;
	uint32_t yh, yl;
	uint32_t rl,rh;
#pragma HLS RESOURCE variable=rl core=AddSub_DSP
#pragma HLS RESOURCE variable=rh core=AddSub_DSP

	xl = (uint32_t) x;
	xh = x>>32;

	yl = (uint32_t) y;
	yh = y>>32;

	rl = yl + xl;
	rh = yh + xh + ((uint32)rl < (uint32)yl);


	uint64_t r;
	r = rh;
	r = r << 32;
	r |= rl;
	return r;
}

uint64_t addv(uint64_t x, uint64_t y){
	uint64_t tmp;
#pragma HLS RESOURCE variable=tmp core=AddSub_DSP
//#pragma HLS RESOURCE variable=tmp latency=1
	//int z = 1;
	tmp = x+y;
	return tmp;
}

#endif

#ifdef NEW_COM
void transmit(uint64_t *input, unsigned char *output) {
	int i, j = 0;
	for (i = 0; i < 8; i++) {
		for (j = 7; j >= 0; j--) {
//#pragma HLS PIPELINE
			output[i * 8 + j] = (unsigned char) (((input[i]) >> (8 * (7 - j)))
					& 255);
		}

	}
}
/*static void SHA512Encode(unsigned char *output, uint64_t  *input) {
 int i ;
 for(i=0;i < 8;i++) {
 output[i*8 + 7] = input[i] & 0xFF;
 output[i*8 + 6] = (input[i] >> 8) & 0xFF; //0xFF:11111111
 output[i*8 + 5] = (input[i] >> 16) & 0xFF;
 output[i*8 + 4] = (input[i] >> 24) & 0xFF;
 output[i*8 + 3] = (input[i] >> 32) & 0xFF;
 output[i*8 + 2] = (input[i] >> 40) & 0xFF;
 output[i*8 + 1] = (input[i] >> 48) & 0xFF;
 output[i*8] = (input[i] >> 56) & 0xFF;

 }
 }*/
static uint64_t BUILD64(uint32_t h, uint32_t l) {
	uint64_t r;
	r = h;
	r = r << 32;
	r |= l;
	return r;
}

#endif

#ifndef NEW_COM
/*uint64 add(uint64 x, uint64 y){
	uint64 r;
#pragma HLS RESOURCE variable=r.lo core=AddSub_DSP
#pragma HLS RESOURCE variable=r.hi core=AddSub_DSP

			r.lo = y.lo + x.lo;
           r.hi = y.hi + x.hi + ((uint32)r.lo < (uint32)y.lo) ;

}*/

static void transout(uint64 *context, unsigned char *digest) {
	for (int i = 0; i < 8; i++) {
		digest[i * 8 + 0] = (context[i].hi >> 24) & 0xFF;
		digest[i * 8 + 1] = (context[i].hi >> 16) & 0xFF;
		digest[i * 8 + 2] = (context[i].hi >> 8) & 0xFF;
		digest[i * 8 + 3] = (context[i].hi >> 0) & 0xFF;
		digest[i * 8 + 4] = (context[i].lo >> 24) & 0xFF;
		digest[i * 8 + 5] = (context[i].lo >> 16) & 0xFF;
		digest[i * 8 + 6] = (context[i].lo >> 8) & 0xFF;
		digest[i * 8 + 7] = (context[i].lo >> 0) & 0xFF;
	}
}

static void update(SHA512_State *s, uint64 a, uint64 b, uint64 c, uint64 d,
		uint64 e, uint64 f, uint64 g, uint64 h) {
#pragma HLS PIPELINE II=1
	uint64 tmp;
	UPDATE(s->h[0], a);
	UPDATE(s->h[1], b);
	UPDATE(s->h[2], c);
	UPDATE(s->h[3], d);
	UPDATE(s->h[4], e);
	UPDATE(s->h[5], f);
	UPDATE(s->h[6], g);UPDATE(s->h[7], h);
}
#endif

static void do_copy_0(unsigned char *dest, unsigned char* source, int len) {
#pragma HLS PIPELINE II=1
	int i;
	for (i = 0; i < 32; i++) {
		if (i < len)
			*(dest + i) = *(source + i);
	}
}

static void SHA512_Core_Init(SHA512_State *s) {
	int i;
	for (i = 0; i < 8; i++) {
#pragma HLS PIPELINE
#ifndef NEW_COM
		s->h[i] = iv[i];
#endif
	}
}
#ifndef NEW_COM

static void SHA512_Block(SHA512_State *s, uint64 *block) {
//#pragma HLS ALLOCATION instances=add limit=1800 operation

//#pragma HLS DATAFLOW
	uint64 a, b, c, d, e, f, g, h;
	uint64 w[80];
#pragma HLS data_pack variable=w
	/*#pragma HLS data_pack variable=a
	 #pragma HLS data_pack variable=b
	 #pragma HLS data_pack variable=c
	 #pragma HLS data_pack variable=d
	 #pragma HLS data_pack variable=e
	 #pragma HLS data_pack variable=f
	 #pragma HLS data_pack variable=g
	 #pragma HLS data_pack variable=h*/

#pragma HLS ARRAY_RESHAPE variable=w cyclic factor=20 dim=1

	int t, tt;

	for (t = 0; t < 16; t++)
		w[t] = block[t];

	for (t = 16; t < 80; t++) {
#pragma HLS PIPELINE
		uint64 p, q, r, tmp;
		smallsigma1(p, tmp, w[t - 2]);
		smallsigma0(q, tmp, w[t - 15]);

		add(r, p, q);
		add(p, r, w[t - 7]);
		add(w[t], p, w[t - 16]);
	}

	a = s->h[0];
	b = s->h[1];
	c = s->h[2];
	d = s->h[3];
	e = s->h[4];
	f = s->h[5];
	g = s->h[6];
	h = s->h[7];

	for (t = 0; t < 80; t += 8) {
//#pragma HLS PIPELINE
		uint64 tmp, p, q, r;

		ROUND(t + 0, a, b, c, d, e, f, g, h);
		ROUND(t + 1, h, a, b, c, d, e, f, g);
		ROUND(t + 2, g, h, a, b, c, d, e, f);
		ROUND(t + 3, f, g, h, a, b, c, d, e);
		ROUND(t + 4, e, f, g, h, a, b, c, d);
		ROUND(t + 5, d, e, f, g, h, a, b, c);
		ROUND(t + 6, c, d, e, f, g, h, a, b);
		ROUND(t + 7, b, c, d, e, f, g, h, a);
	}

	update(s, a, b, c, d, e, f, g, h);
}
#endif

/* ----------------------------------------------------------------------
 * Outer SHA512 algorithm: take an arbitrary length byte string,
 * convert it into 16-doubleword blocks with the prescribed padding
 * at the end, and pass those blocks to the core SHA512 algorithm.
 */

void SHA512_Init(SHA512_State *s) {
#pragma HLS PIPELINE II=1

	int i;
	SHA512_Core_Init(s);
	s->blkused = 0;
#ifndef NEW_COM
	for (i = 0; i < 4; i++)
	 s->len[i] = 0;
#endif
#ifndef FULL_PAD
	for (i = 0; i < BLKSIZE; i++)
		s->block[i] = 0;
#endif
}

void SHA512_Bytes_0(SHA512_State *s, const void *p, int len) {
#pragma HLS PIPELINE II=1
	unsigned char *q = (unsigned char *) p;

	int i;
	/*
	 * Update the length field.
	 */
#ifndef NEW_COM
	uint32 lenw = len;

	for (i = 0; i < 4; i++) {
		s->len[i] += lenw;
		lenw = (s->len[i] < lenw);
	}
#endif

	do_copy_0(s->block, q, len);
	s->blkused = len;

}
#ifndef NEW_COM
void SHA512_Bytes_2(SHA512_State *s) {
	uint64 wordblock[16];
#pragma HLS data_pack variable=wordblock
//#pragma HLS ARRAY_RESHAPE variable=wordblock block factor=8 dim=1

	int i = 0;

	Loop4: for (i = 0; i < 16; i++) {
#pragma HLS PIPELINE II = 1
		uint32 h, l;
		h = (((uint32) s->block[i * 8 + 0]) << 24)
				| (((uint32) s->block[i * 8 + 1]) << 16)
				| (((uint32) s->block[i * 8 + 2]) << 8)
				| (((uint32) s->block[i * 8 + 3]) << 0);
		l = (((uint32) s->block[i * 8 + 4]) << 24)
				| (((uint32) s->block[i * 8 + 5]) << 16)
				| (((uint32) s->block[i * 8 + 6]) << 8)
				| (((uint32) s->block[i * 8 + 7]) << 0);
		BUILD(wordblock[i], h, l);
	}

	SHA512_Block(s, wordblock);

}
#endif
#ifdef NEW_COM

void SHA512_Compute(uint64_t *wordblock, unsigned char *digest) {
#pragma HLS PIPELINE II=1
//#pragma HLS latency min=100 max=300
//#pragma HLS ALLOCATION instances=add limit=600 operation
	/*#pragma HLS ALLOCATION instances=SIGMA1 limit=40 function
	 #pragma HLS ALLOCATION instances=SIGMA0 limit=40 function
	 #pragma HLS ALLOCATION instances=choose limit=40 function
	 #pragma HLS ALLOCATION instances=majority limit=40 function*/

#pragma HLS inline region off

#ifdef ROUND_FUN
	uint64_t W[80], H[8], a, b, c, d, e, f, g, h, T1, T2;

#pragma HLS RESOURCE variable=T1 core=AddSub_DSP
#pragma HLS RESOURCE variable=T2 core=AddSub_DSP
#pragma HLS RESOURCE variable=e core=AddSub_DSP
#pragma HLS RESOURCE variable=a core=AddSub_DSP
	int t;

	H[0] = 0x6a09e667f3bcc908;
	H[1] = 0xbb67ae8584caa73b;
	H[2] = 0x3c6ef372fe94f82b;
	H[3] = 0xa54ff53a5f1d36f1;
	H[4] = 0x510e527fade682d1;
	H[5] = 0x9b05688c2b3e6c1f;
	H[6] = 0x1f83d9abfb41bd6b;
	H[7] = 0x5be0cd19137e2179;

	for ( t = 0; t < 16; t++) {
		W[t] = wordblock[t];
	}
	for ( t = 16; t < 80; t++) {
		//W[t] = (sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16]);
		W[t] = addv(sig1(W[t - 2]), W[t - 7] )+ addv(sig0(W[t - 15]) , W[t - 16]);

	}
	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	for ( t = 0; t < 80; t++) {
		T1 = ((W[t]+(h+SIGMA1(e))) + (choose(e,f,g)+ K[t]));
		//T1 = addv(h , SIGMA1(e) , choose(e, f, g) , K[t] , W[t]);
		//T1 = (h + SIGMA1(e) + choose(e, f, g) + K[t] + W[t]);
		//T2 = addv(SIGMA0(a), majority(a, b, c));
		T2 = (SIGMA0(a) + majority(a, b, c));
		h = g;
		g = f;
		f = e;
		e = d+T1;
		//e = (d + T1);
		d = c;
		c = b;
		b = a;
		//a = addv(T1,T2);
		a = (T1 + T2);
	}

	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;

	transmit(H, digest);

#else
	uint64_t state[8];

	uint64_t S[8];
	//#pragma HLS RESOURCE variable=S core=AddSub_DSP
#pragma HLS ARRAY_PARTITION variable=S complete dim=1
	uint64_t W[80];
#ifndef ROUND_FUN
	uint64_t t0;
	uint64_t t1;
#pragma HLS RESOURCE variable=t0 core=AddSub_DSP
#pragma HLS RESOURCE variable=t1 core=AddSub_DSP
#pragma HLS RESOURCE variable=S[3] core=AddSub_DSP
#pragma HLS RESOURCE variable=S[7] core=AddSub_DSP

#else
	uint64_t t[2];
#endif

#pragma HLS ARRAY_RESHAPE variable=W complete dim=1

	int i = 0;
	int j = 0;

	// SHA512_HASH *Digest;
#ifdef MY_DEBUG
	printf("\nÌî³äºó(1024bits):\n0x");
	for(int index=0;index<128;index++) {
		printf("%02x", block[index]);
	}
	printf("\n");
#endif
	state[0] = 0x6a09e667f3bcc908;
	state[1] = 0xbb67ae8584caa73b;
	state[2] = 0x3c6ef372fe94f82b;
	state[3] = 0xa54ff53a5f1d36f1;
	state[4] = 0x510e527fade682d1;
	state[5] = 0x9b05688c2b3e6c1f;
	state[6] = 0x1f83d9abfb41bd6b;
	state[7] = 0x5be0cd19137e2179;

	for (i = 0; i < 8; i++)
	S[i] = state[i];

	// SHA512Decode(W, block, 128);
	/*for (i = 0; i < 16; i++)
	 LOAD64H(W[i], block + (8 * i));*/

	for (i = 0; i < 16; i++)
	W[i] = wordblock[i];

	for (i = 16; i < 80; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
	}
	for (i = 0; i < 80; i += 8) {
		Sha512Round(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
		Sha512Round(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
		Sha512Round(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
		Sha512Round(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
		Sha512Round(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
		Sha512Round(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
		Sha512Round(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
		Sha512Round(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);

	}

	for (i = 0; i < 8; i++) {
		state[i] += S[i];
	}
	transmit(state, digest);
#endif

	//SHA512Encode(digest, state, 64);
	//SHA512Encode(digest,state);
	/*for (i = 0; i < 8; i++)
	 STORE64H(state[i], digest + (8 * i))*/

#ifdef MY_DEBUG
	for(i = 0; i < 64; i++)
	printf("%02x,",digest[i]);
#endif

}
#endif

void SHA512_Final(SHA512_State *s, unsigned char *digest) {
#pragma HLS inline region off
//#pragma DATAFLOW

	int i, j;
#ifndef LOOKUP
	//int pad;

	//pad = (BLKSIZE - 16) - s->blkused;
#ifndef NEW_COM
	uint32 len[4];
	for (i = 4; i--;) {
		uint32 lenhi = s->len[i];
		uint32 lenlo = i > 0 ? s->len[i - 1] : 0;
		len[i] = (lenhi << 3) | (lenlo >> (32 - 3));
	}
#endif
#ifdef FULL_PAD
	for(j = 0; j < 112; j++) {
#pragma HLS loop_tripcount min=3 max=112
#pragma HLS PIPELINE
		if(j < pad) {
			if(j == 0)
			s->block[s->blkused + j] = 0x80;
			else
			s->block[s->blkused + j] = 0;
		}
	}
#else
	s->block[s->blkused] = 0x80;
#endif

	/*Loop6: for (i = 0; i < 4; i++) {
	 s->block[s->blkused + pad + i * 4 + 0] = (len[3 - i] >> 24) & 0xFF;
	 s->block[s->blkused + pad + i * 4 + 1] = (len[3 - i] >> 16) & 0xFF;
	 s->block[s->blkused + pad + i * 4 + 2] = (len[3 - i] >> 8) & 0xFF;
	 s->block[s->blkused + pad + i * 4 + 3] = (len[3 - i] >> 0) & 0xFF;
	 }*/
#else
//look up table mode
	for(i = 0; i < 128; i++) {
		if(i < 128 - s->blkused)
		s->
#pragma HLS INTERFACE m_axi depth=264 port=p
		block[s->blkused + i] = pad_table[s->blkused][i];
	}
#endif

#ifdef NEW_COM
	uint64_t wordblock[16];
//#pragma HLS ARRAY_RESHAPE variable=wordblock block factor=2 dim=1

	for (i = 0; i < 121; i+=8){
		    wordblock[i/8] = (((uint64_t)((s->block[i]) & 255))<<56)|(((uint64_t)((s->block[i+1]) & 255))<<48) | \
		         (((uint64_t)((s->block[i+2]) & 255))<<40)|(((uint64_t)((s->block[i+3]) & 255))<<32) | \
		         (((uint64_t)((s->block[i+4]) & 255))<<24)|(((uint64_t)((s->block[i+5]) & 255))<<16) | \
		         (((uint64_t)((s->block[i+6]) & 255))<<8)|(((uint64_t)((s->block[i+7]) & 255)));
	}
		/*uint32 h, l;
		h = (((uint32) s->block[i * 8 + 0]) << 24)
		| (((uint32) s->block[i * 8 + 1]) << 16)
		| (((uint32) s->block[i * 8 + 2]) << 8)
		| (((uint32) s->block[i * 8 + 3]) << 0);
		l = (((uint32) s->block[i * 8 + 4]) << 24)
		| (((uint32) s->block[i * 8 + 5]) << 16)
		| (((uint32) s->block[i * 8 + 6]) << 8)
		| (((uint32) s->block[i * 8 + 7]) << 0);
		wordblock[i] = BUILD64(h, l);*/

	wordblock[15] = s->blkused * 8;

	SHA512_Compute(wordblock, digest);
#else
	for (i = 0; i < 4; i++) {
		s->block[s->blkused + pad + i * 4 + 0] = (len[3 - i] >> 24) & 0xFF;
		s->block[s->blkused + pad + i * 4 + 1] = (len[3 - i] >> 16) & 0xFF;
		s->block[s->blkused + pad + i * 4 + 2] = (len[3 - i] >> 8) & 0xFF;
		s->block[s->blkused + pad + i * 4 + 3] = (len[3 - i] >> 0) & 0xFF;
	}
	SHA512_Bytes_2(s);
	transout(s->h, digest);
	/*Loop7: for (i = 0; i < 8; i++) {
	 #pragma HLS PIPELINE II=1
	 digest[i * 8 + 0] = (s->h[i].hi >> 24) & 0xFF;
	 digest[i * 8 + 1] = (s->h[i].hi >> 16) & 0xFF;
	 digest[i * 8 + 2] = (s->h[i].hi >> 8) & 0xFF;
	 digest[i * 8 + 3] = (s->h[i].hi >> 0) & 0xFF;
	 digest[i * 8 + 4] = (s->h[i].lo >> 24) & 0xFF;
	 digest[i * 8 + 5] = (s->h[i].lo >> 16) & 0xFF;
	 digest[i * 8 + 6] = (s->h[i].lo >> 8) & 0xFF;
	 digest[i * 8 + 7] = (s->h[i].lo >> 0) & 0xFF;
	 }*/
#endif
}

void SHA512_Simple(p_in *p, unsigned char len, d_out *digests) {
#pragma HLS INTERFACE ap_fifo depth=32768 port=digests
#pragma HLS INTERFACE ap_fifo depth=32768 port=p
//#pragma HLS allocation instances=ROR64 limit=1 function
	/*#pragma HLS INTERFACE m_axi depth=64 port=digest
	 #pragma HLS INTERFACE m_axi depth=512 port=p
	 #pragma HLS INTERFACE s_axilite port=return*/
//#pragma HLS PIPELINE II=1 enable_flush
#pragma HLS PIPELINE II=1 enable_flush
//#pragma HLS data_pack variable=digests
#pragma HLS data_pack variable=p

//#pragma HLS latency min=50 max=100
//#pragma HLS inline region off

	//unsigned char password[32];

	unsigned char output[64];
#pragma HLS ARRAY_RESHAPE variable=output complete dim=1
	int i;
	int len_0;
	len_0 = (int) len;
	SHA512_State s;
	SHA512_Init(&s);

	for (i = 0; i < 32; i++) {
		s.block[i] = p->passwd[i];
	}

	s.blkused = len_0;

#pragma HLS ARRAY_RESHAPE variable=s.block block factor=32 dim=1
//#pragma HLS ARRAY_RESHAPE variable=password complete dim=1
#pragma HLS ARRAY_RESHAPE variable=digests->digest complete dim=1

#ifdef LOOKUP
#pragma HLS ARRAY_RESHAPE variable=pad_table block factor=128 dim=2
#endif

//---------------------instead SHA512_Bytes call for maxlen < 32-------------------------//
	//SHA512_Bytes_0(&s, password, (int) p->len);
	//SHA512_Bytes_0(&s, password, len_0);
//---------------------instead SHA512_Bytes call for maxlen < 32-------------------------------//
	//SHA512_Final(&s, digests->digest);
	SHA512_Final(&s, output);

	for (i = 0; i < 64; i++)
//#pragma HLS PIPELINE II=1
		digests->digest[i] = output[i];

}
