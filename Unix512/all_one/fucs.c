#include "hashcat_512.h"


int compare_digest_sha512 (const void *p1, const void *p2)
{
  const digest_t *d1 = (const digest_t *) p1;
  const digest_t *d2 = (const digest_t *) p2;

  return memcmp (d1->buf64, d2->buf64, DIGEST_SIZE_SHA512/8);
}

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



uint64_t addv(uint64_t x, uint64_t y){
	uint64_t tmp;
#pragma HLS RESOURCE variable=tmp core=AddSub_DSP
//#pragma HLS RESOURCE variable=tmp latency=1
	//int z = 1;
	tmp = x+y;
	return tmp;
}


void sha512_init(hc_sha512_ctx *ctx) {
	ctx->state[0] = SHA512M_A;
	ctx->state[1] = SHA512M_B;
	ctx->state[2] = SHA512M_C;
	ctx->state[3] = SHA512M_D;
	ctx->state[4] = SHA512M_E;
	ctx->state[5] = SHA512M_F;
	ctx->state[6] = SHA512M_G;
	ctx->state[7] = SHA512M_H;

	ctx->len = 0;
}

void hashcat_sha512(uint64_t digest[8], uint64_t wordblock[16]) {
#pragma HLS PIPELINE II=1
#pragma HLS inline region off

		uint64_t S[8];
#pragma HLS ARRAY_PARTITION variable=S complete dim=1
		uint64_t W[80];
#ifndef ROUND_FUN
		uint64_t t0;
		uint64_t t1;
#else
		uint64_t t[2];
#endif

#pragma HLS ARRAY_RESHAPE variable=W complete dim=1

		int i = 0;
		int j = 0;

		for (i = 0; i < 8; i++)
			S[i] = digest[i];

		// SHA512Decode(W, block, 128);
		/*for (i = 0; i < 16; i++)
		 LOAD64H(W[i], block + (8 * i));*/

		for (i = 0; i < 16; i++)
			W[i] = wordblock[i];

		for (i = 16; i < 80; i++) {
			//W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
			W[i] = addv(Gamma1(W[i - 2]) , W[i - 7]) + addv(Gamma0(W[i - 15]) , W[i - 16]);
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
			digest[i] += S[i];
		}

}

void no_hashcat_sha512(uint64_t digest[8], uint64_t wordblock[16]) {
//#pragma HLS inline region off

	uint64_t W[80], a, b, c, d, e, f, g, h, T1, T2;

/*#pragma HLS RESOURCE variable=T1 core=AddSub_DSP
#pragma HLS RESOURCE variable=T2 core=AddSub_DSP
#pragma HLS RESOURCE variable=e core=AddSub_DSP
#pragma HLS RESOURCE variable=a core=AddSub_DSP*/
	int i,t;

	for ( t = 0; t < 16; t++) {
		W[t] = wordblock[t];
	}
	for ( t = 16; t < 80; t++) {
		//W[t] = (sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16]);
		W[t] = addv(addv(sig1(W[t - 2]) , W[t - 7] ), addv(sig0(W[t - 15]) , W[t - 16]));

	}
	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	for ( t = 0; t < 80; t++) {
		T1 = addv(addv(W[t],addv(h,SIGMA1(e))) , addv(choose(e,f,g), K[t]));
		//T1 = addv(h , SIGMA1(e) , choose(e, f, g) , K[t] , W[t]);
		//T1 = (h + SIGMA1(e) + choose(e, f, g) + K[t] + W[t]);
		//T2 = (SIGMA0(a)+majority(a, b, c));
		T2 = addv(SIGMA0(a) , majority(a, b, c));
		h = g;
		g = f;
		f = e;
		//e = d+T1;
		e = addv(d , T1);
		d = c;
		c = b;
		b = a;
		a = addv(T1,T2);
		//a = (T1 + T2);
	}


	digest[0] = addv(digest[0],a);
	digest[1] = addv(digest[1],b);
	digest[2] = addv(digest[2],c);
	digest[3] = addv(digest[3],d);
	digest[4] = addv(digest[4],e);
	digest[5] = addv(digest[5],f);
	digest[6] = addv(digest[6],g);
	digest[7] = addv(digest[7],h);
	/*	uint64_t S[8];
		uint64_t W[80];
#ifndef ROUND_FUN
		uint64_t t0;
		uint64_t t1;
#else
		uint64_t t[2];
#endif
		int i = 0;
		int j = 0;

		for (i = 0; i < 8; i++)
			S[i] = digest[i];



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
			digest[i] += S[i];
		}*/

}


void sha512_update(hc_sha512_ctx *ctx, const char *buf, int len) {
//#pragma HLS inline region off

//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
	int left = ctx->len & 0x7f;
	int i,j;

	ctx->len += len;

	if (left + len < 128) {
		 for(i = 0; i < len; i++){
			 ctx->buf[left + i] = buf[i];
		 }

		return;
	}
	 for(i = 0; i < 128-left ; i++){
		 ctx->buf[left + i] = buf[i];
	 }

	BYTESWAP64(ctx->w[0]);
	BYTESWAP64(ctx->w[1]);
	BYTESWAP64(ctx->w[2]);
	BYTESWAP64(ctx->w[3]);
	BYTESWAP64(ctx->w[4]);
	BYTESWAP64(ctx->w[5]);
	BYTESWAP64(ctx->w[6]);
	BYTESWAP64(ctx->w[7]);
	BYTESWAP64(ctx->w[8]);
	BYTESWAP64(ctx->w[9]);
	BYTESWAP64(ctx->w[10]);
	BYTESWAP64(ctx->w[11]);
	BYTESWAP64(ctx->w[12]);
	BYTESWAP64(ctx->w[13]);
	BYTESWAP64(ctx->w[14]);
	BYTESWAP64(ctx->w[15]);

	no_hashcat_sha512(ctx->state, ctx->w);
	buf += 128 - left;
	len -= 128 - left;

	//for (j=0; j < MAX_UPDATE;j++) {//while (len > 128)
	while(len > 128){
		//if(len > 128){
		 for(i = 0; i < 128; i++)
			 	 ctx->buf[i] = buf[i];
		//memcpy(ctx->buf, buf, 128);

		BYTESWAP64(ctx->w[0]);
		BYTESWAP64(ctx->w[1]);
		BYTESWAP64(ctx->w[2]);
		BYTESWAP64(ctx->w[3]);
		BYTESWAP64(ctx->w[4]);
		BYTESWAP64(ctx->w[5]);
		BYTESWAP64(ctx->w[6]);
		BYTESWAP64(ctx->w[7]);
		BYTESWAP64(ctx->w[8]);
		BYTESWAP64(ctx->w[9]);
		BYTESWAP64(ctx->w[10]);
		BYTESWAP64(ctx->w[11]);
		BYTESWAP64(ctx->w[12]);
		BYTESWAP64(ctx->w[13]);
		BYTESWAP64(ctx->w[14]);
		BYTESWAP64(ctx->w[15]);

		no_hashcat_sha512(ctx->state, ctx->w);

		buf += 128;
		len -= 128;
		//}
	}
	 for(i = 0; i < len; i++){// i < len
		// if(i < len)
		 ctx->buf[i] = buf[i];
	 }
	//memcpy(ctx->buf, buf, len);
}
void init0_six_final(hc_sha512_ctx *ctx) {
#pragma HLS inline region off

//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
	int left = ctx->len & 0x7f;
	int i;
	 for( i = 0; i < 128 -left; i++){//i < 128 -left
		// if(i < 128 -left)
		 ctx->buf[left + i] = 0;
	 }
		 //memset(ctx->buf + left, 0, 128 - left);

	ctx->buf[left] = 0x80;

	BYTESWAP64(ctx->w[0]);
	BYTESWAP64(ctx->w[1]);
	BYTESWAP64(ctx->w[2]);
	BYTESWAP64(ctx->w[3]);
	BYTESWAP64(ctx->w[4]);
	BYTESWAP64(ctx->w[5]);
	BYTESWAP64(ctx->w[6]);
	BYTESWAP64(ctx->w[7]);
	BYTESWAP64(ctx->w[8]);
	BYTESWAP64(ctx->w[9]);
	BYTESWAP64(ctx->w[10]);
	BYTESWAP64(ctx->w[11]);
	BYTESWAP64(ctx->w[12]);
	BYTESWAP64(ctx->w[13]);

	if (left >= 112) {
		BYTESWAP64(ctx->w[14]);
		BYTESWAP64(ctx->w[15]);

		hashcat_sha512(ctx->state, ctx->w);

		ctx->w[0] = 0;
		ctx->w[1] = 0;
		ctx->w[2] = 0;
		ctx->w[3] = 0;
		ctx->w[4] = 0;
		ctx->w[5] = 0;
		ctx->w[6] = 0;
		ctx->w[7] = 0;
		ctx->w[8] = 0;
		ctx->w[9] = 0;
		ctx->w[10] = 0;
		ctx->w[11] = 0;
		ctx->w[12] = 0;
		ctx->w[13] = 0;
	}

	ctx->w[14] = 0;
	ctx->w[15] = ctx->len * 8;

	hashcat_sha512(ctx->state, ctx->w);

	BYTESWAP64(ctx->state[0]);
	BYTESWAP64(ctx->state[1]);
	BYTESWAP64(ctx->state[2]);
	BYTESWAP64(ctx->state[3]);
	BYTESWAP64(ctx->state[4]);
	BYTESWAP64(ctx->state[5]);
	BYTESWAP64(ctx->state[6]);
	BYTESWAP64(ctx->state[7]);
}

void sha512_final(hc_sha512_ctx *ctx) {
#pragma HLS inline region off

//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
	int left = ctx->len & 0x7f;
	int i;
	 for( i = 0; i < 128 -left; i++){//i < 128 -left
		// if(i < 128 -left)
		 ctx->buf[left + i] = 0;
	 }
		 //memset(ctx->buf + left, 0, 128 - left);

	ctx->buf[left] = 0x80;

	BYTESWAP64(ctx->w[0]);
	BYTESWAP64(ctx->w[1]);
	BYTESWAP64(ctx->w[2]);
	BYTESWAP64(ctx->w[3]);
	BYTESWAP64(ctx->w[4]);
	BYTESWAP64(ctx->w[5]);
	BYTESWAP64(ctx->w[6]);
	BYTESWAP64(ctx->w[7]);
	BYTESWAP64(ctx->w[8]);
	BYTESWAP64(ctx->w[9]);
	BYTESWAP64(ctx->w[10]);
	BYTESWAP64(ctx->w[11]);
	BYTESWAP64(ctx->w[12]);
	BYTESWAP64(ctx->w[13]);

	if (left >= 112) {
		BYTESWAP64(ctx->w[14]);
		BYTESWAP64(ctx->w[15]);

		no_hashcat_sha512(ctx->state, ctx->w);

		ctx->w[0] = 0;
		ctx->w[1] = 0;
		ctx->w[2] = 0;
		ctx->w[3] = 0;
		ctx->w[4] = 0;
		ctx->w[5] = 0;
		ctx->w[6] = 0;
		ctx->w[7] = 0;
		ctx->w[8] = 0;
		ctx->w[9] = 0;
		ctx->w[10] = 0;
		ctx->w[11] = 0;
		ctx->w[12] = 0;
		ctx->w[13] = 0;
	}

	ctx->w[14] = 0;
	ctx->w[15] = ctx->len * 8;

	no_hashcat_sha512(ctx->state, ctx->w);

	BYTESWAP64(ctx->state[0]);
	BYTESWAP64(ctx->state[1]);
	BYTESWAP64(ctx->state[2]);
	BYTESWAP64(ctx->state[3]);
	BYTESWAP64(ctx->state[4]);
	BYTESWAP64(ctx->state[5]);
	BYTESWAP64(ctx->state[6]);
	BYTESWAP64(ctx->state[7]);
}


void loop_sha512_final(hc_sha512_ctx *ctx) {
#pragma HLS inline region off
#pragma HLS PIPELINE II=1
//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
	int left = ctx->len & 0x7f;
	int i;
	/* for( i = 0; i < 128 -left; i++){//i < 128 -left
		// if(i < 128 -left)
		 ctx->buf[left + i] = 0;
	 }*/
		 //memset(ctx->buf + left, 0, 128 - left);

	//ctx->buf[left] = 0x80;

	/*BYTESWAP64(ctx->w[0]);
	BYTESWAP64(ctx->w[1]);
	BYTESWAP64(ctx->w[2]);
	BYTESWAP64(ctx->w[3]);
	BYTESWAP64(ctx->w[4]);
	BYTESWAP64(ctx->w[5]);
	BYTESWAP64(ctx->w[6]);
	BYTESWAP64(ctx->w[7]);
	BYTESWAP64(ctx->w[8]);
	BYTESWAP64(ctx->w[9]);
	BYTESWAP64(ctx->w[10]);
	BYTESWAP64(ctx->w[11]);
	BYTESWAP64(ctx->w[12]);
	BYTESWAP64(ctx->w[13]);*/

	/*if (left >= 112) {
		BYTESWAP64(ctx->w[14]);
		BYTESWAP64(ctx->w[15]);

		hashcat_sha512(ctx->state, ctx->w);

		ctx->w[0] = 0;
		ctx->w[1] = 0;
		ctx->w[2] = 0;
		ctx->w[3] = 0;
		ctx->w[4] = 0;
		ctx->w[5] = 0;
		ctx->w[6] = 0;
		ctx->w[7] = 0;
		ctx->w[8] = 0;
		ctx->w[9] = 0;
		ctx->w[10] = 0;
		ctx->w[11] = 0;
		ctx->w[12] = 0;
		ctx->w[13] = 0;
	}*/

//	ctx->w[14] = 0;
//	ctx->w[15] = ctx->len * 8;
		//ctx->w[15] = left * 8;

	hashcat_sha512(ctx->state, ctx->w);

	BYTESWAP64(ctx->state[0]);
	BYTESWAP64(ctx->state[1]);
	BYTESWAP64(ctx->state[2]);
	BYTESWAP64(ctx->state[3]);
	BYTESWAP64(ctx->state[4]);
	BYTESWAP64(ctx->state[5]);
	BYTESWAP64(ctx->state[6]);
	BYTESWAP64(ctx->state[7]);
}
