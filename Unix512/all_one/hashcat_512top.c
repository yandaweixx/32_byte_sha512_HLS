#include "hashcat_512.h"

void do_copy(uint64_t *input, uint64_t *output) {
#pragma HLS PIPELINE
	int i,j;
	for (i = 0; i < 8; i++) {
		output[i] = input[i];
	}
}

void up_buf(uint8_t *input, hc_sha512_ctx *output, int len) {
//#pragma HLS PIPELINE
	int i;
	int left = output->len & 0x7f;
	output->len += len;
	for (i = 0; i < len; i++) {
		//if(i < len)
		output->buf[left + i] = input[i];
	}
}
void loop_up_buf(uint8_t *input, hc_sha512_ctx *output) {
//#pragma HLS PIPELINE
	int i;
	int left = output->len & 0x7f;
	output->len += 64;
	for (i = 0; i < 64; i++) {
		//if(i < len)
		output->buf[left + i] = input[i];
	}
}
void transmit(uint64_t *input, unsigned char *output) {
	int i, j = 0;
	for (i = 0; i < 8; i++) {
		for (j = 7; j >= 0; j--) {
//#pragma HLS PIPELINE
			output[i * 8 + j] = (unsigned char) (((input[i]) >> (8 * j)) & 255); //这里并不是真正意义上的uint64_t转unsigned char，没有位变化，只是顺序变为unsigned char
		}

	}
}
#ifdef OP_WPC
void wpc_copy(uint64_t wpc[8][16], uint64_t *l_p_bytes0, uint64_t *l_s_bytes0,
		int pw_len, int salt_len) {
	int i,j;
	uint8_t tmp_value[64];
	uint8_t tmp_w[128];
	uint64_t tmp;
	int lenw, k;
	for (i = 0; i < 8; i++) {
		int block_len = 0;

		if (i & 1) {
			transmit(l_p_bytes0, tmp_value);
			for (j = 0; j < pw_len; j++) {
				tmp_w[block_len + j] = tmp_value[j];
				// PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
			}
			block_len += pw_len;
		} else {
			block_len += 64;
		}

		if (i & 2) {
			transmit(l_s_bytes0, tmp_value);
			for (j = 0; j < salt_len; j++) {
				tmp_w[block_len + j] = tmp_value[j];

				// PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_s_bytes0, j));
			}
			block_len += salt_len;

		}

		if (i & 4) {
			transmit(l_p_bytes0, tmp_value);
			for (j = 0; j < pw_len; j++) {
				tmp_w[block_len + j] = tmp_value[j];
				//PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
			}
			block_len += pw_len;

		}

		if (i & 1) {
			block_len += 64;
		} else {
			transmit(l_p_bytes0, tmp_value);
			for (j = 0; j < pw_len; j++) {
				tmp_w[block_len + j] = tmp_value[j];
				// PUTCHAR64_BE (wpc[i], block_len++, GETCHAR64_BE (l_p_bytes0, j));
			}
			block_len += pw_len;

		}
		tmp_w[block_len] = 0x80;
		for (k = 0; k < 16; k++) {
			for (j = 0; j < 8; j++) {
				wpc[i][k] = (wpc[i][k] << 8) | tmp_w[k * 8 + j];
			}
		}
		// PUTCHAR64_BE (wpc[i], block_len, 0x80);

		wpc[i][15] = block_len * 8;
	}

}
#endif

void hashing_01800(char pwd[MAX_PASSW], int password0_len, int salt_len,
		char salt[MAX_SALT], digest_t *digest) {
//#pragma HLS DATA_PACK variable=digest
//#pragma HLS DATAFLOW
#pragma HLS allocation instances=sha512_update limit=1 function
#pragma HLS allocation instances=sha512_final limit=1 function
#pragma HLS INTERFACE ap_fifo port=digest
#pragma HLS INTERFACE ap_fifo port=salt
#pragma HLS INTERFACE ap_fifo port=pwd

//#pragma HLS allocation instances=hashcat_sha512 limit=1 function

#pragma HLS inline off

	int i,j = 0;

	char password0_buf[MAX_PASSW];
	char salt_buf[MAX_SALT];
#ifdef FIXED_SIX
	password0_len = 6;
	salt_len = 8;
#endif

	for (i = 0; i < password0_len; i++) {
//#pragma HLS PIPELINE
		//if(i < password0_len)
		password0_buf[i] = pwd[i];
	}

	for (i = 0; i < salt_len; i++) {
//#pragma HLS PIPELINE
		//if(i < salt_len)
		salt_buf[i] = salt[i];
	}

//#pragma HLS PIPELINE
	//digest_t digest_target;

	//printf("DAVID DEBUG filename is %s, Line: %d, Func:%s, salt->iteration %d\n", __FILE__, __LINE__, __func__,password0_len );

	//char *password0_buf = (unsigned char *) in->buf8;

	//int password3_len = in->len;

	unsigned char tmp_state[64];

//DAVID

	hc_sha512_ctx ctx0;
	hc_sha512_ctx alt_ctx0;
	hc_sha512_ctx p_bytes0;
	hc_sha512_ctx s_bytes0;

	/*#pragma HLS ARRAY_RESHAPE variable=ctx0.state block factor=2 dim=1
	 #pragma HLS ARRAY_RESHAPE variable=ctx0.w complete dim=1
	 //#pragma HLS ARRAY_RESHAPE variable=ctx0.buf complete dim=1

	 #pragma HLS ARRAY_RESHAPE variable=alt_ctx0.state block factor=2 dim=1
	 #pragma HLS ARRAY_RESHAPE variable=alt_ctx0.w complete dim=1
	 //#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.buf complete dim=1

	 #pragma HLS ARRAY_RESHAPE variable=s_bytes0.state block factor=2 dim=1
	 #pragma HLS ARRAY_RESHAPE variable=s_bytes0.w complete dim=1
	 //#pragma HLS ARRAY_RESHAPE variable=s_bytes0.buf complete dim=1

	 #pragma HLS ARRAY_RESHAPE variable=p_bytes0.state block factor=2 dim=1
	 #pragma HLS ARRAY_RESHAPE variable=p_bytes0.w complete dim=1
	 //#pragma HLS ARRAY_RESHAPE variable=p_bytes0.buf complete dim=1*/
	/* Prepare for the real work.  */
	sha512_init(&ctx0);

	/* Add the key string.  */
	up_buf(password0_buf, &ctx0, password0_len);
	//sha512_update(&ctx0, password0_buf, password0_len);

	/* The last part is the salt string.  This must be at most 16
	 characters and it ends at the first `$' character (for
	 compatibility with existing implementations).  */
	up_buf(salt_buf, &ctx0, salt_len);
	//sha512_update(&ctx0, salt_buf, salt_len);

	/* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
	 final result will be added to the first context.  */
	sha512_init(&alt_ctx0);

	/* Add key.  */
	up_buf(password0_buf, &alt_ctx0, password0_len);
	//sha512_update(&alt_ctx0, password0_buf, password0_len);

	/* Add salt.  */
	up_buf(salt_buf, &alt_ctx0, salt_len);
	//sha512_update(&alt_ctx0, salt_buf, salt_len);

	/* Add key again.  */
	up_buf(password0_buf, &alt_ctx0, password0_len);
	//sha512_update(&alt_ctx0, password0_buf, password0_len);

	/* Now get result of this (64 bytes) and add it to the other context.  */
#ifdef FIXED_SIX
	init0_six_final(&alt_ctx0);
#else
	sha512_final(&alt_ctx0);
#endif
	/* Add for any character in the key one byte of the alternate sum.  */

	transmit(alt_ctx0.state, tmp_state);

	up_buf(tmp_state, &ctx0, password0_len);
	//sha512_update(&ctx0, tmp_state, password0_len);

	//sha512_update(&ctx0, (char *) alt_ctx0.state, password0_len);

	/* Take the binary representation of the length of the key and for every
	 1 add the alternate sum, for every 0 the key.  */

	int cnt;

	for (cnt = password0_len; cnt > 0; cnt >>= 1) {
		if ((cnt & 1) != 0) {
			transmit(alt_ctx0.state, tmp_state);
			sha512_update(&ctx0, tmp_state, 64);
			//sha512_update(&ctx0, (char *) alt_ctx0.state, 64);
		} else
			sha512_update(&ctx0, password0_buf, password0_len);
	}

	/* Create intermediate result.  */
	sha512_final(&ctx0);

	/* Start computation of P byte sequence.  */
	sha512_init(&p_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < password0_len; cnt++) {
		sha512_update(&p_bytes0, password0_buf, password0_len);
	}

	/* Finish the state.  */
	sha512_final(&p_bytes0);

	/* Start computation of S byte sequence.  */
	sha512_init(&s_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < 16 + ((unsigned char*) ctx0.state)[0]; cnt++) {
		sha512_update(&s_bytes0, salt_buf, salt_len);
	}

	/* Finish the state.  */
	sha512_final(&s_bytes0);

	/* sse2 specific */
#ifdef HASHCAT
	uint64_t plain_alt_ctx[8];
#ifndef NO_FUNC_COPY
	do_copy( ctx0.state, plain_alt_ctx);
#endif

#ifdef NO_FUNC_COPY
	plain_alt_ctx[0] = ctx0.state[0];
	plain_alt_ctx[1] = ctx0.state[1];
	plain_alt_ctx[2] = ctx0.state[2];
	plain_alt_ctx[3] = ctx0.state[3];
	plain_alt_ctx[4] = ctx0.state[4];
	plain_alt_ctx[5] = ctx0.state[5];
	plain_alt_ctx[6] = ctx0.state[6];
	plain_alt_ctx[7] = ctx0.state[7];
#endif //NO_FUNC_COPY
#pragma HLS ARRAY_RESHAPE variable=plain_alt_ctx block factor=2 dim=1

	uint64_t plain_p_bytes[8];
#ifndef NO_FUNC_COPY
	do_copy(p_bytes0.state,plain_p_bytes);
#endif
#ifdef NO_FUNC_COPY
	plain_p_bytes[0] = p_bytes0.state[0];
	plain_p_bytes[1] = p_bytes0.state[1];
	plain_p_bytes[2] = p_bytes0.state[2];
	plain_p_bytes[3] = p_bytes0.state[3];
	plain_p_bytes[4] = p_bytes0.state[4];
	plain_p_bytes[5] = p_bytes0.state[5];
	plain_p_bytes[6] = p_bytes0.state[6];
	plain_p_bytes[7] = p_bytes0.state[7];
#endif //NO_FUNC_COPY
#pragma HLS ARRAY_RESHAPE variable=plain_p_bytes block factor=2 dim=1

	uint64_t plain_s_bytes[8];
#ifndef NO_FUNC_COPY
	do_copy(s_bytes0.state, plain_s_bytes);
#endif
#ifdef NO_FUNC_COPY
	plain_s_bytes[0] = s_bytes0.state[0];
	plain_s_bytes[1] = s_bytes0.state[1];
	plain_s_bytes[2] = s_bytes0.state[2];
	plain_s_bytes[3] = s_bytes0.state[3];
	plain_s_bytes[4] = s_bytes0.state[4];
	plain_s_bytes[5] = s_bytes0.state[5];
	plain_s_bytes[6] = s_bytes0.state[6];
	plain_s_bytes[7] = s_bytes0.state[7];
#endif//NO_FUNC_COPY
#pragma HLS ARRAY_RESHAPE variable=plain_s_bytes block factor=2 dim=1

	hc_sha512_ctx loop_ctx;

//#pragma HLS ARRAY_RESHAPE variable=loop_ctx.buf complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.state block factor=2 dim=1

	//int db1,db2,db3,db4,db5,db6;
	//db1=db2=db3=db4=db5=db6=0;

#pragma HLS ARRAY_RESHAPE variable=ctx0.state block factor=2 dim=1
#pragma HLS ARRAY_RESHAPE variable=ctx0.w complete dim=1
	//#pragma HLS ARRAY_RESHAPE variable=ctx0.buf complete dim=1

	//#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.state block factor=2 dim=1
	//#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.w complete dim=1
	//#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=s_bytes0.state block factor=2 dim=1
#pragma HLS ARRAY_RESHAPE variable=s_bytes0.w complete dim=1
	//#pragma HLS ARRAY_RESHAPE variable=s_bytes0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=p_bytes0.state block factor=2 dim=1
#pragma HLS ARRAY_RESHAPE variable=p_bytes0.w complete dim=1
	//#pragma HLS ARRAY_RESHAPE variable=p_bytes0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=tmp_state complete dim=1

#pragma HLS ARRAY_RESHAPE variable=digest->buf64 complete dim=1

#pragma HLS ARRAY_RESHAPE variable=salt_buf complete dim=1
#pragma HLS ARRAY_RESHAPE variable=password0_buf complete dim=1
	/* Repeatedly run the collected hash value through SHA512 to
	 burn CPU cycles.  */

	for (cnt = 0; cnt < 5000; cnt++) {
		/* New context.  */
		//digest_sha512_sse2_t sse2_ctx;
		sha512_init(&loop_ctx);
		//sha512_init_sse2(&sse2_ctx);
		plain_t loop_plain;
		//	plain_t sse2_plain[4];
		loop_plain.len = 0;
		//	plain_init(sse2_plain);
		/* Add key or last result.  */
		if ((cnt & 1) != 0) {
			//Cond_Region1:{
#pragma HLS occurrence cycle=2
			transmit(plain_p_bytes,tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);
			//sha512_update(&loop_ctx, tmp_state, password0_len);
			//}
			//	db1++;
			//sha512_update(&loop_ctx,(char *)plain_p_bytes.buf64 , plain_p_bytes.len);
		}
		//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		else {
			//Cond_Region2:{
#pragma HLS occurrence cycle=2

			transmit(plain_alt_ctx,tmp_state);
			up_buf(tmp_state, &loop_ctx, 64);
			//sha512_update(&loop_ctx, tmp_state, 64);
			//}
			//db2++;
			//sha512_update(&loop_ctx, (char *)plain_alt_ctx.buf64, plain_alt_ctx.len);
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_alt_ctx);
		}
		/* Add salt for numbers not divisible by 3.  */
		if (cnt % 3 != 0) {
			transmit(plain_s_bytes,tmp_state);
			up_buf(tmp_state, &loop_ctx, salt_len);
			//sha512_update(&loop_ctx, tmp_state, salt_len);
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_s_bytes);
			//	db3++;
		}
		/* Add key for numbers not divisible by 7.  */
		if (cnt % 7 != 0) {
			transmit(plain_p_bytes,tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);

			//	sha512_update(&loop_ctx, tmp_state, password0_len);
			//	db4++;
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		}
		/* Add key or last result.  */
		if ((cnt & 1) != 0) {
			//	Cond_Region3:{

#pragma HLS occurrence cycle=2

			transmit(plain_alt_ctx,tmp_state);
			up_buf(tmp_state, &loop_ctx, 64);

			//sha512_update(&loop_ctx, tmp_state, 64);
			//}
			//db5++;
		}		//	sha512_update_sse2(sse2_plain, &sse2_ctx, plain_alt_ctx);
		else {
			//	Cond_Region4:{

#pragma HLS occurrence cycle=2

			transmit(plain_p_bytes,tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);

			//sha512_update(&loop_ctx,tmp_state, password0_len);
			//}
			//db6++;
			//	sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		}
		/* Create intermediate [SIC] result.  */
		loop_sha512_final(&loop_ctx);
		//	sha512_final_sse2(sse2_plain, &sse2_ctx);
#ifndef NO_FUNC_COPY
		do_copy(loop_ctx.state, plain_alt_ctx );
#endif
#ifdef NO_FUNC_COPY
		plain_alt_ctx[0] = loop_ctx.state[0];
		//plain_alt_ctx.buf64[0] = sse2_ctx.buf64[0];
		plain_alt_ctx[1] = loop_ctx.state[1];
		//plain_alt_ctx.buf64[1] = sse2_ctx.buf64[4];
		plain_alt_ctx[2] = loop_ctx.state[2];
		//plain_alt_ctx.buf64[2] = sse2_ctx.buf64[8];
		plain_alt_ctx[3] = loop_ctx.state[3];
		//plain_alt_ctx.buf64[3] = sse2_ctx.buf64[12];
		plain_alt_ctx[4] = loop_ctx.state[4];
		//plain_alt_ctx.buf64[4] = sse2_ctx.buf64[16];
		plain_alt_ctx[5] = loop_ctx.state[5];
		//plain_alt_ctx.buf64[5] = sse2_ctx.buf64[20];
		plain_alt_ctx[6] = loop_ctx.state[6];
		//	plain_alt_ctx.buf64[6] = sse2_ctx.buf64[24];
		plain_alt_ctx[7] = loop_ctx.state[7];
		//plain_alt_ctx.buf64[7] = sse2_ctx.buf64[28];
#endif
		/*BYTESWAP64(plain_alt_ctx.buf64[0]);
		 BYTESWAP64(plain_alt_ctx.buf64[1]);
		 BYTESWAP64(plain_alt_ctx.buf64[2]);
		 BYTESWAP64(plain_alt_ctx.buf64[3]);
		 BYTESWAP64(plain_alt_ctx.buf64[4]);
		 BYTESWAP64(plain_alt_ctx.buf64[5]);
		 BYTESWAP64(plain_alt_ctx.buf64[6]);
		 BYTESWAP64(plain_alt_ctx.buf64[7]);*/
	}
#else //HASHCAT

	/* Repeatedly run the collected hash value through SHA512 to
	 burn CPU cycles.  */
#ifdef OP_WPC

	int wpc_len[8];

	wpc_len[0] = 64 + 0 + 0 + password0_len;
	wpc_len[1] = password0_len + 0 + 0 + 64;
	wpc_len[2] = 64 + salt_len + 0 + password0_len;
	wpc_len[3] = password0_len + salt_len + 0 + 64;
	wpc_len[4] = 64 + 0 + password0_len + password0_len;
	wpc_len[5] = password0_len + 0 + password0_len + 64;
	wpc_len[6] = 64 + salt_len + password0_len + password0_len;
	wpc_len[7] = password0_len + salt_len + password0_len + 64;

	hc_sha512_ctx wpc[8];
	unsigned char loop_temp_state[64];
#pragma HLS ARRAY_RESHAPE variable=loop_temp_state complete dim=1

/*#pragma HLS ARRAY_RESHAPE variable=wpc[0].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[0].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[1].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[1].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[2].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[2].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[3].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[3].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[4].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[4].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[5].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[5].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[6].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[6].state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[7].w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc[7].state complete dim=1*/
	for (i = 0; i < 8; i++){
		for(j = 0; j < 16; j++){
			wpc[i].w[j]=0;
		}
		wpc[i].len = 0;
		wpc[i].w[15] = wpc_len[i]*8;
		wpc[i].buf[wpc_len[i]] = 0x80;
	}

	for (i = 0; i < 8; i++) {
		//int block_len = 0;

		if (i & 1) {
			transmit(p_bytes0.state, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);

		} else {
			wpc[i].len += 64;
		}

		if (i & 2) {
			transmit(s_bytes0.state, tmp_state);
			up_buf(tmp_state, &wpc[i], salt_len);

		}

		if (i & 4) {
			transmit(p_bytes0.state, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);
		}

		if (i & 1) {
			wpc[i].len += 64;
		} else {
			transmit(p_bytes0.state, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);

		}

	}

	//wpc_copy(wpc, p_bytes0.state, s_bytes0.state, password0_len, salt_len);

	uint64_t l_alt_result[8];
	hc_sha512_ctx block;
#pragma HLS ARRAY_RESHAPE variable=l_alt_result complete dim=1
#pragma HLS ARRAY_RESHAPE variable=block.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=block.w complete dim=1

	l_alt_result[0] = ctx0.state[0];
	l_alt_result[1] = ctx0.state[1];
	l_alt_result[2] = ctx0.state[2];
	l_alt_result[3] = ctx0.state[3];
	l_alt_result[4] = ctx0.state[4];
	l_alt_result[5] = ctx0.state[5];
	l_alt_result[6] = ctx0.state[6];
	l_alt_result[7] = ctx0.state[7];

#else
	/*unsigned char tmp_state_p[64];
	 unsigned char tmp_state_s[64];
	 transmit(p_bytes0.state,tmp_state_p);
	 transmit(s_bytes0.state,tmp_state_s);*/

#endif//OP_WPC

	for (cnt = 0; cnt < 5000; cnt++) {
#ifdef OP_WPC

		/* Repeatedly run the collected hash value through SHA512 to burn
		 CPU cycles.  */

		int k, p;
		const int j1 = (cnt & 1) ? 1 : 0;
		const int j3 = (cnt % 3) ? 2 : 0;
		const int j7 = (cnt % 7) ? 4 : 0;

		const int pc = j1 + j3 + j7;

		block.w[0] = wpc[pc].w[0];
		block.w[1] = wpc[pc].w[1];
		block.w[2] = wpc[pc].w[2];
		block.w[3] = wpc[pc].w[3];
		block.w[4] = wpc[pc].w[4];
		block.w[5] = wpc[pc].w[5];
		block.w[6] = wpc[pc].w[6];
		block.w[7] = wpc[pc].w[7];
		block.w[8] = wpc[pc].w[8];
		block.w[9] = wpc[pc].w[9];
		block.w[10] = wpc[pc].w[10];
		block.w[11] = wpc[pc].w[11];
		block.w[12] = wpc[pc].w[12];
		block.w[13] = wpc[pc].w[13];
		block.w[14] = wpc[pc].w[14];
		block.w[15] = wpc[pc].w[15];
		block.len = wpc[pc].len;

		block.state[0] = SHA512M_A;
		block.state[1] = SHA512M_B;
		block.state[2] = SHA512M_C;
		block.state[3] = SHA512M_D;
		block.state[4] = SHA512M_E;
		block.state[5] = SHA512M_F;
		block.state[6] = SHA512M_G;
		block.state[7] = SHA512M_H;

		if (j1) {
			//const int block_len = wpc_len[pc];
			block.len -= 64;
			transmit(l_alt_result, loop_temp_state);
			loop_up_buf(loop_temp_state, &block);

			/*  for ( k = 0, p = block_len - 64; k < 64; k++, p++)
			 {
			 PUTCHAR64_BE (block, p, GETCHAR64_BE (l_alt_result, k));
			 }*/
		} else {
			block.len = 0;
			transmit(l_alt_result, loop_temp_state);
			loop_up_buf(loop_temp_state, &block);
			/*wpc[pc].w[0] = l_alt_result[0];
			 wpc[pc].w[1] = l_alt_result[1];
			 wpc[pc].w[2] = l_alt_result[2];
			 wpc[pc].w[3] = l_alt_result[3];
			 wpc[pc].w[4] = l_alt_result[4];
			 wpc[pc].w[5] = l_alt_result[5];
			 wpc[pc].w[6] = l_alt_result[6];
			 wpc[pc].w[7] = l_alt_result[7];*/
		}
		block.len = wpc_len[pc];

		BYTESWAP64(block.w[0]);
		BYTESWAP64(block.w[1]);
		BYTESWAP64(block.w[2]);
		BYTESWAP64(block.w[3]);
		BYTESWAP64(block.w[4]);
		BYTESWAP64(block.w[5]);
		BYTESWAP64(block.w[6]);
		BYTESWAP64(block.w[7]);
		BYTESWAP64(block.w[8]);
		BYTESWAP64(block.w[9]);
		BYTESWAP64(block.w[10]);
		BYTESWAP64(block.w[11]);
		BYTESWAP64(block.w[12]);
		BYTESWAP64(block.w[13]);

		loop_sha512_final(&block);

		l_alt_result[0] = block.state[0];
		l_alt_result[1] = block.state[1];
		l_alt_result[2] = block.state[2];
		l_alt_result[3] = block.state[3];
		l_alt_result[4] = block.state[4];
		l_alt_result[5] = block.state[5];
		l_alt_result[6] = block.state[6];
		l_alt_result[7] = block.state[7];
		// hashcat_sha512(l_alt_result, block);
		// sha512_transform_transport (block, l_alt_result);

#else
		hc_sha512_ctx loop_ctx;

#pragma HLS ARRAY_RESHAPE variable=loop_ctx.buf complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.state complete dim=1

		sha512_init(&loop_ctx);
		/* Add key or last result.  */
		if ((cnt & 1) != 0) {
			transmit(p_bytes0.state,tmp_state);
			// do_copy_1(tmp_state_p, &loop_ctx, password0_len);

			sha512_update(&loop_ctx, tmp_state, password0_len);
			//sha512_update(&loop_ctx,(char *)plain_p_bytes.buf64 , plain_p_bytes.len);
		}
		//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		else {
			transmit(ctx0.state,tmp_state);

			// do_copy_1(tmp_state, &loop_ctx, 64);

			sha512_update(&loop_ctx, tmp_state, 64);
			//sha512_update(&loop_ctx, (char *)plain_alt_ctx.buf64, plain_alt_ctx.len);
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_alt_ctx);
		}
		/* Add salt for numbers not divisible by 3.  */
		if (cnt % 3 != 0) {

			//do_copy_1(tmp_state_s,&loop_ctx, salt_len);

			transmit(s_bytes0.state,tmp_state);
			sha512_update(&loop_ctx, tmp_state, salt_len);
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_s_bytes);
		}
		/* Add key for numbers not divisible by 7.  */
		if (cnt % 7 != 0) {
			// do_copy_1(tmp_state_p,&loop_ctx, password0_len);

			transmit(p_bytes0.state,tmp_state);
			sha512_update(&loop_ctx, tmp_state, password0_len);
			//sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		}
		/* Add key or last result.  */
		if ((cnt & 1) != 0) {
			transmit(ctx0.state,tmp_state);
			// do_copy_1(tmp_state, &loop_ctx, 64);

			sha512_update(&loop_ctx, tmp_state, 64);
		}		//	sha512_update_sse2(sse2_plain, &sse2_ctx, plain_alt_ctx);
		else {
			// do_copy_1(tmp_state_p, &loop_ctx, password0_len);

			transmit(p_bytes0.state,tmp_state);
			sha512_update(&loop_ctx,tmp_state,password0_len);
			//	sha512_update_sse2(sse2_plain, &sse2_ctx, plain_p_bytes);
		}

		/* Create intermediate [SIC] result.  */
		sha512_final(&loop_ctx);
		//	sha512_final_sse2(sse2_plain, &sse2_ctx);
		do_copy(loop_ctx.state, ctx0.state);
#endif //NO_WPC

#ifdef NO_FUNC_COPY
		ctx0.state[0] = loop_ctx.state[0];
		//plain_alt_ctx.buf64[0] = sse2_ctx.buf64[0];
		ctx0.state[1] = loop_ctx.state[1];
		//plain_alt_ctx.buf64[1] = sse2_ctx.buf64[4];
		ctx0.state[2] = loop_ctx.state[2];
		//plain_alt_ctx.buf64[2] = sse2_ctx.buf64[8];
		ctx0.state[3] = loop_ctx.state[3];
		//plain_alt_ctx.buf64[3] = sse2_ctx.buf64[12];
		ctx0.state[4] = loop_ctx.state[4];
		//plain_alt_ctx.buf64[4] = sse2_ctx.buf64[16];
		ctx0.state[5] = loop_ctx.state[5];
		//plain_alt_ctx.buf64[5] = sse2_ctx.buf64[20];
		ctx0.state[6] = loop_ctx.state[6];
		//	plain_alt_ctx.buf64[6] = sse2_ctx.buf64[24];
		ctx0.state[7] = loop_ctx.state[7];

#endif//NO_FUNC_COPY
	}
#endif//HASHCAT

	//	do_copy( ctx0.state, digest->buf64);
#ifdef HASHCAT
	digest->buf64[0] = plain_alt_ctx[0];
	digest->buf64[1] = plain_alt_ctx[1];
	digest->buf64[2] = plain_alt_ctx[2];
	digest->buf64[3] = plain_alt_ctx[3];
	digest->buf64[4] = plain_alt_ctx[4];
	digest->buf64[5] = plain_alt_ctx[5];
	digest->buf64[6] = plain_alt_ctx[6];
	digest->buf64[7] = plain_alt_ctx[7];
#else
#ifdef OP_WPC
	digest->buf64[0] = l_alt_result[0];
	digest->buf64[1] = l_alt_result[1];
	digest->buf64[2] = l_alt_result[2];
	digest->buf64[3] = l_alt_result[3];
	digest->buf64[4] = l_alt_result[4];
	digest->buf64[5] = l_alt_result[5];
	digest->buf64[6] = l_alt_result[6];
	digest->buf64[7] = l_alt_result[7];
#else
	digest->buf64[0] = ctx0.state[0];
	digest->buf64[1] = ctx0.state[1];
	digest->buf64[2] = ctx0.state[2];
	digest->buf64[3] = ctx0.state[3];
	digest->buf64[4] = ctx0.state[4];
	digest->buf64[5] = ctx0.state[5];
	digest->buf64[6] = ctx0.state[6];
	digest->buf64[7] = ctx0.state[7];
#endif
#endif//HASHCAT
	//printf("DAVID DEBUG filename is %s, Line: %d, Func:%s, salt->iteration %d\n", __FILE__, __LINE__, __func__,password0_len );
	//printf("DAVID DEBUG loop if times :%d %d %d %d %d %d \n",db1,db2,db3,db4,db5,db6);

}
