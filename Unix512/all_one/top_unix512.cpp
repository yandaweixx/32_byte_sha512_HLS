#include "top_unix512.hpp"

void do_copy(uint64_t *input, uint64_t *output) {
#pragma HLS PIPELINE
	int i, j;
	for (i = 0; i < 8; i++) {
		output[i] = input[i];
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



void do_loop_copy(uint64_t *input, uint64_t *output) {
#pragma HLS PIPELINE
	int i, j;
	for (i = 0; i < 8; i++) {
		output[i] = input[i];
	}
}

void copy16(uint64_t *input, uint64_t *output) {
#pragma HLS PIPELINE
	int i, j;
	for (i = 0; i < 16; i++) {
		output[i] = input[i];
	}
}

void up_buf(uint8_t *input, hc_sha512_ctx *output, int len) {
//#pragma HLS PIPELINE
#pragma HLS inline off
	int i;
	int left = output->len & 0x7f;
	output->len += len;
	for (i = 0; i < len; i++) {
#pragma HLS LOOP_TRIPCOUNT min=6 max=64
		//if(i < len)
		output->buf[left + i] = input[i];
	}
}





void loop_up_buf(uint8_t *input, uint8_t *output, int used, int len) {
//#pragma HLS PIPELINE
	int i;
	//int left = output->len & 0x7f;
	//output->len += 64;
	for (i = 0; i < 64; i++) {
		if (i < len)
			output[used + i] = input[i];
	}
}

void online_transmit(uint64_t *input0, uint64_t *input1, uint64_t *input2,
		unsigned char output[3][64]) {
	int i, j, k = 0;

	for (i = 0; i < 8; i++) {
		for (j = 7; j >= 0; j--) {
//#pragma HLS PIPELINE
			output[0][i * 8 + j] = (unsigned char) (((input0[i]) >> (8 * j))
					& 255); //这里并不是真正意义上的uint64_t转unsigned char，没有位变化，只是顺序变为unsigned char
			output[1][i * 8 + j] = (unsigned char) (((input1[i]) >> (8 * j))
					& 255);
			output[2][i * 8 + j] = (unsigned char) (((input2[i]) >> (8 * j))
					& 255);
		}
	}

}

void transmit16(uint64_t *input, unsigned char *output) {
	int i, j = 0;
	for (i = 0; i < 16; i++) {
		for (j = 7; j >= 0; j--) {
//#pragma HLS PIPELINE
			output[i * 8 + j] = (unsigned char) (((input[i]) >> (8 * j)) & 255); //这里并不是真正意义上的uint64_t转unsigned char，没有位变化，只是顺序变为unsigned char
		}

	}
}

void do_init(hc_sha512_ctx *ctx0, hc_sha512_ctx *alt_ctx0,
		hc_sha512_ctx *p_bytes0, hc_sha512_ctx *s_bytes0,
		uint8_t *password0_buf, uint8_t *salt_buf, int password0_len,
		int salt_len, uint8_t *wpc_alt_ctx0, uint8_t * wpc_p_bytes0,
		uint8_t *wpc_s_bytes0) {
#pragma HLS inline off

//#pragma HLS LOOP_FLATTEN off
//#pragma HLS allocation instances=sha512_update limit=1 function
//#pragma HLS allocation instances=sha512_final limit=1 function
	int i, j, cnt;
	uint8_t tmp_state[64];

	/* Prepare for the real work.  */
	sha512_init(ctx0);

	/* Add the key string.  */
	up_buf(password0_buf, ctx0, password0_len);
	//sha512_update(&ctx0, password0_buf, password0_len);

	/* The last part is the salt string.  This must be at most 16
	 characters and it ends at the first `$' character (for
	 compatibility with existing implementations).  */
	up_buf(salt_buf, ctx0, salt_len);
	//sha512_update(&ctx0, salt_buf, salt_len);

	/* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
	 final result will be added to the first context.  */
	sha512_init(alt_ctx0);

	/* Add key.  */
	up_buf(password0_buf, alt_ctx0, password0_len);
	//sha512_update(&alt_ctx0, password0_buf, password0_len);

	/* Add salt.  */
	up_buf(salt_buf, alt_ctx0, salt_len);
	//sha512_update(&alt_ctx0, salt_buf, salt_len);

	/* Add key again.  */
	up_buf(password0_buf, alt_ctx0, password0_len);
	//sha512_update(&alt_ctx0, password0_buf, password0_len);

	/* Now get result of this (64 bytes) and add it to the other context.  */

	sha512_final(alt_ctx0);

	/* Add for any character in the key one byte of the alternate sum.  */

	transmit(alt_ctx0->state, tmp_state);

	up_buf(tmp_state, ctx0, password0_len);
	//sha512_update(&ctx0, tmp_state, password0_len);

	//sha512_update(&ctx0, (char *) alt_ctx0.state, password0_len);

	/* Take the binary representation of the length of the key and for every
	 1 add the alternate sum, for every 0 the key.  */

	for (cnt = password0_len; cnt > 0; cnt >>= 1) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=8
		if ((cnt & 1) != 0) {
			transmit(alt_ctx0->state, tmp_state);
			sha512_update(ctx0, tmp_state, 64);
			//sha512_update(&ctx0, (char *) alt_ctx0.state, 64);
		} else
			sha512_update(ctx0, password0_buf, password0_len);
	}

	/* Create intermediate result.  */
	sha512_final(ctx0);

	/* Start computation of P byte sequence.  */
	sha512_init(p_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < password0_len; cnt++) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=32
		sha512_update(p_bytes0, password0_buf, password0_len);
	}

	/* Finish the state.  */
	sha512_final(p_bytes0);

	/* Start computation of S byte sequence.  */
	sha512_init(s_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < 16 + ((unsigned char*) ctx0->state)[0]; cnt++) {
#pragma HLS LOOP_TRIPCOUNT min=16 max=32
		sha512_update(s_bytes0, salt_buf, salt_len);
	}

	/* Finish the state.  */
	sha512_final(s_bytes0);

	/*for (i = 0; i < 8; i++) {
	 wpc_alt_ctx0[i] = ctx0->state[i];
	 wpc_p_bytes0[i] = p_bytes0->state[i];
	 wpc_s_bytes0[i] = s_bytes0->state[i];
	 }*/

	for (i = 0; i < 8; i++) {
		for (j = 7; j >= 0; j--) {
			//#pragma HLS PIPELINE
			wpc_alt_ctx0[i * 8 + j] = (unsigned char) (((ctx0->state[i])
					>> (8 * j)) & 255); //这里并不是真正意义上的uint64_t转unsigned char，没有位变化，只是顺序变为unsigned char
			wpc_p_bytes0[i * 8 + j] = (unsigned char) (((p_bytes0->state[i])
					>> (8 * j)) & 255);
			wpc_s_bytes0[i * 8 + j] = (unsigned char) (((s_bytes0->state[i])
					>> (8 * j)) & 255);
		}
	}

}
/*void do_loop_int_2(hc_sha512_ctx *block, hc_sha512_ctx *ctx0_t, int cnt,
 int password0_len, int salt_len, uint64_t wpc[][8][16], int *wpc_len, int flag) {
 #pragma HLS ARRAY_RESHAPE variable=block object complete

 unsigned char loop_temp_state[64];
 #pragma HLS ARRAY_RESHAPE variable=loop_temp_state complete

 int k, p;
 const int j1 = (cnt & 1) ? 1 : 0;
 const int j3 = (cnt % 3) ? 2 : 0;
 const int j7 = (cnt % 7) ? 4 : 0;

 const int pc = j1 + j3 + j7;

 block->w[0] = wpc[flag][pc][0];
 block->w[1] = wpc[flag][pc][1];
 block->w[2] = wpc[flag][pc][2];
 block->w[3] = wpc[flag][pc][3];
 block->w[4] = wpc[flag][pc][4];
 block->w[5] = wpc[flag][pc][5];
 block->w[6] = wpc[flag][pc][6];
 block->w[7] = wpc[flag][pc][7];
 block->w[8] = wpc[flag][pc][8];
 block->w[9] = wpc[flag][pc][9];
 block->w[10] = wpc[flag][pc][10];
 block->w[11] = wpc[flag][pc][11];
 block->w[12] = wpc[flag][pc][12];
 block->w[13] = wpc[flag][pc][13];
 block->w[14] = wpc[flag][pc][14];
 block->w[15] = wpc[flag][pc][15];
 block->len = wpc_len[pc];

 block->state[0] = SHA512M_A;
 block->state[1] = SHA512M_B;
 block->state[2] = SHA512M_C;
 block->state[3] = SHA512M_D;
 block->state[4] = SHA512M_E;
 block->state[5] = SHA512M_F;
 block->state[6] = SHA512M_G;
 block->state[7] = SHA512M_H;

 if (j1) {
 //const int block_len = wpc_len[pc];
 block->len -= 64;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);


 } else {
 block->len = 0;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);

 }
 block->len = wpc_len[pc];

 BYTESWAP64(block->w[0]);
 BYTESWAP64(block->w[1]);
 BYTESWAP64(block->w[2]);
 BYTESWAP64(block->w[3]);
 BYTESWAP64(block->w[4]);
 BYTESWAP64(block->w[5]);
 BYTESWAP64(block->w[6]);
 BYTESWAP64(block->w[7]);
 BYTESWAP64(block->w[8]);
 BYTESWAP64(block->w[9]);
 BYTESWAP64(block->w[10]);
 BYTESWAP64(block->w[11]);
 BYTESWAP64(block->w[12]);
 BYTESWAP64(block->w[13]);

 }*/

/*void do_loop_int_2(hc_sha512_ctx *block, hc_sha512_ctx *ctx0_t, int cnt,
 int password0_len, int salt_len, hc_sha512_ctx *wpc, int *wpc_len) {
 unsigned char loop_temp_state[64];
 int k, p;
 const int j1 = (cnt & 1) ? 1 : 0;
 const int j3 = (cnt % 3) ? 2 : 0;
 const int j7 = (cnt % 7) ? 4 : 0;

 const int pc = j1 + j3 + j7;

 block->w[0] = wpc[pc].w[0];
 block->w[1] = wpc[pc].w[1];
 block->w[2] = wpc[pc].w[2];
 block->w[3] = wpc[pc].w[3];
 block->w[4] = wpc[pc].w[4];
 block->w[5] = wpc[pc].w[5];
 block->w[6] = wpc[pc].w[6];
 block->w[7] = wpc[pc].w[7];
 block->w[8] = wpc[pc].w[8];
 block->w[9] = wpc[pc].w[9];
 block->w[10] = wpc[pc].w[10];
 block->w[11] = wpc[pc].w[11];
 block->w[12] = wpc[pc].w[12];
 block->w[13] = wpc[pc].w[13];
 block->w[14] = wpc[pc].w[14];
 block->w[15] = wpc[pc].w[15];
 block->len = wpc[pc].len;

 block->state[0] = SHA512M_A;
 block->state[1] = SHA512M_B;
 block->state[2] = SHA512M_C;
 block->state[3] = SHA512M_D;
 block->state[4] = SHA512M_E;
 block->state[5] = SHA512M_F;
 block->state[6] = SHA512M_G;
 block->state[7] = SHA512M_H;

 if (j1) {
 //const int block_len = wpc_len[pc];
 block->len -= 64;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);


 } else {
 block->len = 0;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);

 }
 block->len = wpc_len[pc];

 BYTESWAP64(block->w[0]);
 BYTESWAP64(block->w[1]);
 BYTESWAP64(block->w[2]);
 BYTESWAP64(block->w[3]);
 BYTESWAP64(block->w[4]);
 BYTESWAP64(block->w[5]);
 BYTESWAP64(block->w[6]);
 BYTESWAP64(block->w[7]);
 BYTESWAP64(block->w[8]);
 BYTESWAP64(block->w[9]);
 BYTESWAP64(block->w[10]);
 BYTESWAP64(block->w[11]);
 BYTESWAP64(block->w[12]);
 BYTESWAP64(block->w[13]);

 }*/

/* Add key or last result.  */
/*		if ((cnt & 1) != 0) {
 //Cond_Region1:{
 //#pragma HLS occurrence cycle=2
 transmit(p_bytes0,tmp_state[0]);
 loop_up_buf(tmp_state[0],loop_state, block_len, password0_len );
 block_len += password0_len;

 }
 else {

 transmit(ctx0_t,tmp_state[1]);
 loop_up_buf(tmp_state[1],loop_state, block_len, 64 );
 block_len += 64;


 }
 if (cnt % 3 != 0) {
 transmit(s_bytes0,tmp_state[2]);
 loop_up_buf(tmp_state[2],loop_state, block_len, salt_len );
 block_len += salt_len;

 }
 if (cnt % 7 != 0) {
 transmit(p_bytes0,tmp_state[3]);
 loop_up_buf(tmp_state[3],loop_state, block_len, password0_len );
 block_len += password0_len;


 }
 if ((cnt & 1) != 0) {
 //	Cond_Region3:{

 //#pragma HLS occurrence cycle=2
 transmit(ctx0_t,tmp_state[4]);
 loop_up_buf(tmp_state[4],loop_state, block_len, 64 );
 block_len += 64;

 }
 else {


 transmit(p_bytes0,tmp_state[5]);
 loop_up_buf(tmp_state[5],loop_state, block_len, password0_len );
 block_len += password0_len;

 }

 loop_state[block_len] = 0x80;
 for (i = 0; i < 14; i++)
 LOAD64H(block_w[i], loop_state + i * 8)


 block_w[14] = 0;
 block_w[15] = block_len *8;

 }*/

/*void do_loop_int(hc_sha512_ctx *block, hc_sha512_ctx *ctx0_t, int cnt,
 int password0_len, int salt_len, hc_sha512_ctx *wpc, int *wpc_len) {
 unsigned char loop_temp_state[64];
 int k, p;
 const int j1 = (cnt & 1) ? 1 : 0;
 const int j3 = (cnt % 3) ? 2 : 0;
 const int j7 = (cnt % 7) ? 4 : 0;

 const int pc = j1 + j3 + j7;

 block->w[0] = wpc[pc].w[0];
 block->w[1] = wpc[pc].w[1];
 block->w[2] = wpc[pc].w[2];
 block->w[3] = wpc[pc].w[3];
 block->w[4] = wpc[pc].w[4];
 block->w[5] = wpc[pc].w[5];
 block->w[6] = wpc[pc].w[6];
 block->w[7] = wpc[pc].w[7];
 block->w[8] = wpc[pc].w[8];
 block->w[9] = wpc[pc].w[9];
 block->w[10] = wpc[pc].w[10];
 block->w[11] = wpc[pc].w[11];
 block->w[12] = wpc[pc].w[12];
 block->w[13] = wpc[pc].w[13];
 block->w[14] = wpc[pc].w[14];
 block->w[15] = wpc[pc].w[15];
 block->len = wpc[pc].len;

 block->state[0] = SHA512M_A;
 block->state[1] = SHA512M_B;
 block->state[2] = SHA512M_C;
 block->state[3] = SHA512M_D;
 block->state[4] = SHA512M_E;
 block->state[5] = SHA512M_F;
 block->state[6] = SHA512M_G;
 block->state[7] = SHA512M_H;

 if (j1) {
 //const int block_len = wpc_len[pc];
 block->len -= 64;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);


 } else {
 block->len = 0;
 transmit(ctx0_t->state, loop_temp_state);
 loop_up_buf(loop_temp_state, block);

 }
 block->len = wpc_len[pc];

 BYTESWAP64(block->w[0]);
 BYTESWAP64(block->w[1]);
 BYTESWAP64(block->w[2]);
 BYTESWAP64(block->w[3]);
 BYTESWAP64(block->w[4]);
 BYTESWAP64(block->w[5]);
 BYTESWAP64(block->w[6]);
 BYTESWAP64(block->w[7]);
 BYTESWAP64(block->w[8]);
 BYTESWAP64(block->w[9]);
 BYTESWAP64(block->w[10]);
 BYTESWAP64(block->w[11]);
 BYTESWAP64(block->w[12]);
 BYTESWAP64(block->w[13]);

 }*/

//void do_loop(uint64_t *digest[][8], uint64_t* wpc_alt_ctx0[][8], uint64_t *wpc_p_bytes0[][8], uint64_t *wpc_s_bytes0[][8],int password0_len[GROUP_LENGTH], int salt_len[GROUP_LENGTH]) {
void do_loop(uint8_t (*wpc_alt_ctx0)[64],
		uint8_t wpc_p_bytes0[GROUP_LENGTH][64],
		uint8_t wpc_s_bytes0[GROUP_LENGTH][64], int password0_len,
		int salt_len) {

//#pragma HLS DATAFLOW
#pragma HLS inline off
	int i, j, k,j1,j3,j7,pc;
	int cnt;

	//uint64_t tmp_alt_ctx0[GROUP_LENGTH][8];
	uint8_t hashout[64];

	int lpp = password0_len;
	int lss = salt_len;


	uint8_t out1[GROUP_LENGTH][64];
	uint8_t out2[GROUP_LENGTH][64];

	uint8_t wpc0[128];
	uint64_t wpc064[16];

#pragma HLS ARRAY_RESHAPE variable=out1 complete dim=2
#pragma HLS ARRAY_RESHAPE variable=out2 complete dim=2
#pragma HLS ARRAY_RESHAPE variable=wpc0 complete dim=1
#pragma HLS ARRAY_RESHAPE variable=wpc064 complete dim=1

#pragma HLS ARRAY_RESHAPE variable=hashout complete dim=1

	int wpc_len[8];

	wpc_len[0] = 64 + 0 + 0 + password0_len;
	wpc_len[1] = password0_len + 0 + 0 + 64;
	wpc_len[2] = 64 + salt_len + 0 + password0_len;
	wpc_len[3] = password0_len + salt_len + 0 + 64;
	wpc_len[4] = 64 + 0 + password0_len + password0_len;
	wpc_len[5] = password0_len + 0 + password0_len + 64;
	wpc_len[6] = 64 + salt_len + password0_len + password0_len;
	wpc_len[7] = password0_len + salt_len + password0_len + 64;

	for (i = 0; i < GROUP_LENGTH; i++) {
		for (j = 0; j < 64; j++)
#pragma HLS PIPELINE II=1
			out1[i][j] = wpc_alt_ctx0[i][j];

	}

//hc_sha512_ctx tmp_ctx[GROUP_LENGTH];
	uint64_t loop_ctx_state[8];

	for (cnt = 0; cnt < 5000; cnt++) {


		 j1 = (cnt & 1) ? 1 : 0;
		 j3 = (cnt % 3) ? 2 : 0;
		 j7 = (cnt % 7) ? 4 : 0;

		 pc = j1 + j3 + j7;

		switch (pc) {
		case 0:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0; i <64; i++)
					wpc0[i] = out1[j][i];
				for(i = 64; i < 64 + lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i-64];
				for(i = 64+lp; i<112; i++)
					wpc0[i] = 0;

				/*for (i = 0; i < 112; i++) {
					if (i < 64 + lp) {
						if (i < 64)
							wpc0[i] = out1[j][i];
						else {
							wpc0[i] = wpc_p_bytes0[j][i - 64];
						}
					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[64 + lp] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out2[j][i] = hashout[i];
			}

			break;
		case 1:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0 ; i < lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i];
				for(i = lp; i < lp+64; i++)
					wpc0[i] = out2[j][i - lp];
				for(i = lp+64; i <112; i++)
					wpc0[i] = 0x00;
				/*for (i = 0; i < 112; i++) {
					if (i < lp + 64) {
						if (i < lp)
							wpc0[i] = wpc_p_bytes0[j][i];
						else {
							wpc0[i] = out2[j][i - lp];
						}
					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[64 + lp] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out1[j][i] = hashout[i];
			}

			break;
		case 2:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0; i < 64; i++)
					wpc0[i] = out1[j][i];

				for(i = 64; i < 64+ls; i++)
					wpc0[i] = wpc_s_bytes0[j][i - 64];

				for(i = 64+ ls; i< 64+ls+lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i - 64 - ls];

				for(i = 64+ls+lp; i< 112; i++)
					wpc0[i] = 0x00;

				/*for (i = 0; i < 112; i++) {
					if (i < 64 + ls + lp) {
						if (i < 64)
							wpc0[i] = out1[j][i];
						else if (i < 64 + ls) {
							wpc0[i] = wpc_s_bytes0[j][i - 64];
						} else
							wpc0[i] = wpc_p_bytes0[j][i - 64 - ls];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[64 + ls + lp] = 0x80;

				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out2[j][i] = hashout[i];

			}
			break;
		case 3:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0 ; i < lp; i ++)
					wpc0[i] = wpc_p_bytes0[j][i];
				for(i = lp; i < lp+ls; i++)
					wpc0[i] = wpc_s_bytes0[j][i - lp];
				for(i = lp+ls ; i < lp+ls+64; i++)
					wpc0[i] = out2[j][i - lp - ls];
				for(i = lp + ls + 64; i < 112; i ++)
					wpc0[i] = 0;

				/*for (i = 0; i < 112; i++) {
					if (i < lp + ls + 64) {
						if (i < lp)
							wpc0[i] = wpc_p_bytes0[j][i];
						else if (i < lp + ls) {
							wpc0[i] = wpc_s_bytes0[j][i - lp];
						} else
							wpc0[i] = out2[j][i - lp - ls];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[lp + ls + 64] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out1[j][i] = hashout[i];
			}
			break;
		case 4:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1

				for(i = 0; i < 64; i ++)
					wpc0[i] = out1[j][i];
				for(i = 64; i < 64+lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i - 64];
				for(i = 64+lp; i < 64+lp+lp; i ++)
					wpc0[i] = wpc_p_bytes0[j][i - 64 - lp];
				for(i= 64+ lp + lp; i < 112; i++)
					wpc0[i] = 0;
				/*for (i = 0; i < 112; i++) {
					if (i < 64 + lp + lp) {
						if (i < 64)
							wpc0[i] = out1[j][i];
						else if (i < 64 + lp) {
							wpc0[i] = wpc_p_bytes0[j][i - 64];
						} else
							wpc0[i] = wpc_p_bytes0[j][i - 64 - lp];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[64 + lp + lp] = 0x80;

				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out2[j][i] = hashout[i];
			}
			break;
		case 5:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0; i < lp; i ++)
					wpc0[i] = wpc_p_bytes0[j][i];
				for(i = lp; i < lp+lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i - lp];
				for(i= lp+lp; i < lp+lp+64; i++)
					wpc0[i] = out2[j][i - lp - lp];
				for(i= lp+lp+64; i < 112; i++)
					wpc0[i] = 0;
				/*for (i = 0; i < 112; i++) {
					if (i < lp + lp + 64) {
						if (i < lp)
							wpc0[i] = wpc_p_bytes0[j][i];
						else if (i < lp + lp) {
							wpc0[i] = wpc_p_bytes0[j][i - lp];
						} else
							wpc0[i] = out2[j][i - lp - lp];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[lp + lp + 64] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out1[j][i] = hashout[i];

			}
			break;
		case 6:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0; i < 64; i ++)
					wpc0[i] = out1[j][i];
				for(i = 64; i< 64+ls; i++)
					wpc0[i] = wpc_s_bytes0[j][i - 64];
				for(i=64+ls; i<64+ls+lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i - 64 - ls];
				for(i=64+ls+lp; i< 64+ls+lp+lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i - 64 - ls - lp];

				for(i=64+ls+lp+lp; i< 112; i++)
					wpc0[i] = 0;
				/*for (i = 0; i < 112; i++) {
					if (i < 64 + ls + lp + lp) {
						if (i < 64)
							wpc0[i] = out1[j][i];
						else if (i < 64 + ls) {
							wpc0[i] = wpc_s_bytes0[j][i - 64];
						} else if (i < 64 + ls + lp)
							wpc0[i] = wpc_p_bytes0[j][i - 64 - ls];
						else
							wpc0[i] = wpc_p_bytes0[j][i - 64 - ls - lp];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[64 + ls + lp + lp] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out2[j][i] = hashout[i];
			}
			break;
		case 7:
			for (j = 0; j < GROUP_LENGTH; j++) {
#pragma HLS PIPELINE II=1
				for(i = 0 ; i < lp; i++)
					wpc0[i] = wpc_p_bytes0[j][i];
				for(i = lp; i < lp+ls; i++)
					wpc0[i] = wpc_s_bytes0[j][i - lp];
				for(i = lp + ls; i < lp+ls+lp;i++)
					wpc0[i] = wpc_p_bytes0[j][i - lp - ls];
				for(i = lp+ls +lp; i < lp+ls+lp+64; i++)
					wpc0[i] = out2[j][i - lp - ls - lp];
				for(i = lp+ls+lp+64; i < 112; i++)
					wpc0[i] = 0;

				/*for (i = 0; i < 112; i++) {
					if (i < lp + ls + lp + 64) {
						if (i < lp)
							wpc0[i] = wpc_p_bytes0[j][i];
						else if (i < lp + ls) {
							wpc0[i] = wpc_s_bytes0[j][i - lp];
						} else if (i < lp + ls + lp)
							wpc0[i] = wpc_p_bytes0[j][i - lp - ls];
						else
							wpc0[i] = out2[j][i - lp - ls - lp];

					} else
						wpc0[i] = 0x00;
				}*/
				wpc0[lp + ls + lp + 64] = 0x80;
				for (i = 0; i < 14; i++)
					LOAD64H(wpc064[i], wpc0 + i * 8)

				wpc064[14] = 0;
				wpc064[15] = wpc_len[pc] * 8;
				david_hash(wpc064, hashout);

				for (i = 0; i < 64; i++)
					out1[j][i] = hashout[i];

			}
			break;
		}//case

	}		//5000
	for (i = 0; i < GROUP_LENGTH; i++) {
		for (j = 0; j < 8; j++) {
#pragma HLS PIPELINE II=1
			wpc_alt_ctx0[i][j] = out1[i][j];
		}
	}

}

void hashing_01800(hls::stream<pwd_t> &pwd, hls::stream<int> &password0_len,
		hls::stream<int> &salt_len, hls::stream<salt_t> &salt,
		hls::stream<digest_t> &digest) {
#pragma HLS DATA_PACK variable=pwd
#pragma HLS DATA_PACK variable=salt
#pragma HLS DATA_PACK variable=digest
//#pragma HLS STREAM variable=digest

	/*#pragma HLS INTERFACE ap_fifo port=digest depth=2048
	 #pragma HLS INTERFACE ap_fifo port=salt depth=2048
	 #pragma HLS INTERFACE ap_fifo port=pwd depth=2048*/

//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
#pragma HLS inline off
	int i, j, m = 0;
	int cnt;
	uint8_t password0_buf[MAX_PASSW];
	uint8_t salt_buf[MAX_SALT];
	int tmp_pass_len;
	int tmp_salt_len;

	int tmp_pass_len_1;
	int tmp_salt_len_1;

	/*for (j = 0; j < GROUP_LENGTH; j++) {
	 for (i = 0; i < MAX_PASSW; i++) {
	 //#pragma HLS PIPELINE
	 password0_buf[j][i] = pwd[j][i];
	 }
	 }
	 for (j = 0; j < GROUP_LENGTH; j++) {
	 for (i = 0; i < MAX_SALT; i++) {
	 //#pragma HLS PIPELINE
	 salt_buf[j][i] = salt[j][i];
	 }
	 }*/

	pwd_t tmp_passwd;
	salt_t tmp_salt;
	digest_t tmp_digest;
#pragma HLS ARRAY_RESHAPE variable=tmp_digest.buf64 complete dim=1

	hc_sha512_ctx ctx0;
	hc_sha512_ctx alt_ctx0;
	hc_sha512_ctx p_bytes0;
	hc_sha512_ctx s_bytes0;

//hc_sha512_ctx wpc[GROUP_LENGTH][8];

	uint8_t wpc_alt_ctx0[GROUP_LENGTH][64];
	uint8_t wpc_p_bytes0[GROUP_LENGTH][64];
	uint8_t wpc_s_bytes0[GROUP_LENGTH][64];

	for (i = 0; i < GROUP_LENGTH; i++) {
		tmp_digest.buf64[i] = 0x00;
	}
//	int wpc_len[GROUP_LENGTH][8];
//uint64_t wpc_w[GROUP_LENGTH][8][16];
//#pragma HLS ARRAY_PARTITION variable=wpc_w complete dim=0
#pragma HLS ARRAY_PARTITION variable=wpc_alt_ctx0 complete dim=2
#pragma HLS ARRAY_RESHAPE variable=wpc_p_bytes0 complete dim=2
#pragma HLS ARRAY_RESHAPE variable=wpc_s_bytes0 complete dim=2
//#pragma HLS ARRAY_RESHAPE variable=digest object complete dim=2
//#pragma HLS ARRAY_RESHAPE variable=digest object dim=1

	//uint64_t inter_digests[GROUP_LENGTH][8];
//#pragma HLS ARRAY_RESHAPE variable=inter_digests complete dim=2
//#pragma HLS ARRAY_RESHAPE variable=tmp_digest.buf64 complete dim=1
//#pragma HLS DATAFLOW

	for (i = 0; i < GROUP_LENGTH; i++) {
//#pragma HLS LOOP_FLATTEN off
		tmp_passwd = pwd.read();
		tmp_salt = salt.read();
		tmp_pass_len = tmp_pass_len_1 = password0_len.read();
		tmp_salt_len = tmp_salt_len_1 = salt_len.read();
		for (j = 0; j < MAX_PASSW; j++) {
			if (j < tmp_pass_len) {
				password0_buf[j] = tmp_passwd.passwd[j];
			}		//pwd[i].passwd[j];
			if (j < tmp_salt_len)
				salt_buf[j] = tmp_salt.salt[j];

		}
		do_init(&ctx0, &alt_ctx0, &p_bytes0, &s_bytes0, password0_buf, salt_buf,
				tmp_pass_len, tmp_salt_len, wpc_alt_ctx0[i], wpc_p_bytes0[i],
				wpc_s_bytes0[i]);
	}

	do_loop(wpc_alt_ctx0, wpc_p_bytes0, wpc_s_bytes0, tmp_pass_len_1,
			tmp_salt_len_1);

	for (i = 0; i < GROUP_LENGTH; i++) {
		for (j = 0; j < 8; j++) {
#pragma HLS PIPELINE II=1
			PUT64BE(tmp_digest.buf64[j],wpc_alt_ctx0[i] + j*8)
			//tmp_digest.buf64[j] = wpc_alt_ctx0[i][j];
		}
		digest.write(tmp_digest);
	}

}
