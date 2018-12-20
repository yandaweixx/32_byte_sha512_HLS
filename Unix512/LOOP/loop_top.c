#include "loop_top.h"
void loop_5k(uint64_t *digest, uint64_t *input1, uint64_t *input2, uint64_t *input3,int password0_len, int salt_len) {
#pragma HLS DATA_PACK variable=input1
#pragma HLS DATA_PACK variable=input2
#pragma HLS DATA_PACK variable=input3
#pragma HLS DATA_PACK variable=digest

//#pragma HLS allocation instances=sha512_update limit=1 function
//#pragma HLS allocation instances=sha512_final limit=1 function
#pragma HLS inline region off
//#pragma HLS allocation instances=do_copy limit=1 function

#pragma HLS INTERFACE ap_fifo depth=8 port=digest
#pragma HLS INTERFACE ap_fifo depth=8 port=input1
#pragma HLS INTERFACE ap_fifo depth=8 port=input2
#pragma HLS INTERFACE ap_fifo depth=8 port=input3
#pragma HLS inline region off
//#pragma HLS INTERFACE ap_fifo port=input

	unsigned char tmp_state[64];
//#pragma HLS ARRAY_RESHAPE variable=tmp_state complete dim=1

	uint64_t plain_s_bytes[8];
	uint64_t plain_alt_ctx[8];
	uint64_t plain_p_bytes[8];
#ifndef WPC_OP
	hc_sha512_ctx loop_ctx;
//#pragma HLS ARRAY_RESHAPE variable=loop_ctx.buf complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=loop_ctx.state complete dim=1
#endif
	int i,j;

	for( i = 0; i < 8; i++){
		plain_alt_ctx[i] = input1[i];
		plain_p_bytes[i] = input2[i];
		plain_s_bytes[i] = input3[i];
	}


	/*do_copy(input1, plain_alt_ctx);
	do_copy(input2, plain_p_bytes);
	do_copy(input3, plain_s_bytes);*/

/*#pragma HLS ARRAY_RESHAPE variable=plain_s_bytes complete dim=1
#pragma HLS ARRAY_RESHAPE variable=plain_alt_ctx complete dim=1
#pragma HLS ARRAY_RESHAPE variable=plain_p_bytes complete dim=1*/

#ifdef WPC_OP
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
			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);

		} else {
			wpc[i].len += 64;
		}

		if (i & 2) {
			transmit(plain_s_bytes, tmp_state);
			up_buf(tmp_state, &wpc[i], salt_len);

		}

		if (i & 4) {
			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);
		}

		if (i & 1) {
			wpc[i].len += 64;
		} else {
			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &wpc[i], password0_len);

		}

	}

	//wpc_copy(wpc, p_bytes0.state, s_bytes0.state, password0_len, salt_len);

	uint64_t l_alt_result[8];
	hc_sha512_ctx block;
//#pragma HLS ARRAY_RESHAPE variable=l_alt_result complete dim=1
#pragma HLS ARRAY_RESHAPE variable=block.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=block.w complete dim=1

	l_alt_result[0] = plain_alt_ctx[0];
	l_alt_result[1] = plain_alt_ctx[1];
	l_alt_result[2] = plain_alt_ctx[2];
	l_alt_result[3] = plain_alt_ctx[3];
	l_alt_result[4] = plain_alt_ctx[4];
	l_alt_result[5] = plain_alt_ctx[5];
	l_alt_result[6] = plain_alt_ctx[6];
	l_alt_result[7] = plain_alt_ctx[7];

#endif
	for (int cnt = 0; cnt < 5000; cnt++) {

#ifdef WPC_OP

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

#else

		/* New context.  */
		sha512_init(&loop_ctx);
		//plain_t loop_plain;
		//loop_plain.len = 0;
		/* Add key or last result.  */

		if ((cnt & 1) != 0) {

			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);
			//sha512_update(&loop_ctx, tmp_state, password0_len);

		} else {

			transmit(plain_alt_ctx, tmp_state);
			up_buf(tmp_state, &loop_ctx, 64);

			//sha512_update(&loop_ctx, tmp_state, 64);

		}
		if (cnt % 3 != 0) {
			transmit(plain_s_bytes, tmp_state);
			up_buf(tmp_state, &loop_ctx, salt_len);
			//sha512_update(&loop_ctx, tmp_state, salt_len);

		}
		if (cnt % 7 != 0) {
			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);

			//sha512_update(&loop_ctx, tmp_state, password0_len);

		}
		if ((cnt & 1) != 0) {

			transmit(plain_alt_ctx, tmp_state);
			up_buf(tmp_state, &loop_ctx, 64);

			//sha512_update(&loop_ctx, tmp_state, 64);

		} else {

			transmit(plain_p_bytes, tmp_state);
			up_buf(tmp_state, &loop_ctx, password0_len);

			//sha512_update(&loop_ctx, tmp_state, password0_len);

		}
		/* Create intermediate [SIC] result.  */
		sha512_final(&loop_ctx);
		do_copy(loop_ctx.state, plain_alt_ctx);

#endif
	}
#ifdef WPC_OP
	digest[0] = l_alt_result[0];
	digest[1] = l_alt_result[1];
	digest[2] = l_alt_result[2];
	digest[3] = l_alt_result[3];
	digest[4] = l_alt_result[4];
	digest[5] = l_alt_result[5];
	digest[6] = l_alt_result[6];
	digest[7] = l_alt_result[7];
#else
	do_copy(plain_alt_ctx, digest);
#endif
	/*digest[0] = plain_alt_ctx[0];
	 digest[1] = plain_alt_ctx[1];
	 digest[2] = plain_alt_ctx[2];
	 digest[3] = plain_alt_ctx[3];
	 digest[4] = plain_alt_ctx[4];
	 digest[5] = plain_alt_ctx[5];
	 digest[6] = plain_alt_ctx[6];
	 digest[7] = plain_alt_ctx[7];*/

}
