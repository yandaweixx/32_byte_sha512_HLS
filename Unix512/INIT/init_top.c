#include "init_top.h"
void hashing_01800_part1(char pwd[MAX_PASSW],int password0_len, int salt_len, char salt[MAX_SALT] , fifo_midel *output) {
#pragma HLS DATA_PACK variable=output
#pragma HLS INTERFACE ap_fifo depth=32576 port=output
//#pragma HLS DATAFLOW
//#pragma HLS allocation instances=sha512_update limit=1 function
//#pragma HLS allocation instances=hashcat_sha512 limit=1 function
//#pragma HLS INTERFACE ap_fifo depth=2048 port=digest->buf64
#pragma HLS INTERFACE ap_fifo depth=512 port=salt
#pragma HLS INTERFACE ap_fifo depth=512 port=pwd


//#pragma HLS allocation instances=hashcat_sha512 limit=1 function

//#pragma HLS ARRAY_RESHAPE variable=digest->buf64 complete dim=1
#pragma HLS inline off

	int i = 0;

	char password0_buf[MAX_PASSW];
	char salt_buf[MAX_SALT];

	for(i = 0; i < password0_len; i++){
#pragma HLS loop_tripcount min=1 max=32
		password0_buf[i] = pwd[i];
	}

	for(i = 0; i < salt_len; i++){
#pragma HLS loop_tripcount min=8 max=16 avg=8
		salt_buf[i] = salt[i];
	}


/*#pragma HLS ARRAY_RESHAPE variable=salt_buf complete dim=1
#pragma HLS ARRAY_RESHAPE variable=password0_buf complete dim=1*/


    unsigned char tmp_state[64];
//#pragma HLS ARRAY_RESHAPE variable=tmp_state complete dim=1



	hc_sha512_ctx ctx0;	hc_sha512_ctx alt_ctx0;	hc_sha512_ctx p_bytes0;	hc_sha512_ctx s_bytes0;


/*#pragma HLS ARRAY_RESHAPE variable=ctx0.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=ctx0.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=ctx0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=alt_ctx0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=s_bytes0.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=s_bytes0.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=s_bytes0.buf complete dim=1

#pragma HLS ARRAY_RESHAPE variable=p_bytes0.state complete dim=1
#pragma HLS ARRAY_RESHAPE variable=p_bytes0.w complete dim=1
#pragma HLS ARRAY_RESHAPE variable=p_bytes0.buf complete dim=1*/
	/* Prepare for the real work.  */
	sha512_init(&ctx0);

	/* Add the key string.  */

	up_buf(password0_buf, &ctx0, password0_len);
	up_buf(salt_buf,&ctx0, salt_len);



	sha512_init(&alt_ctx0);
	/* Add key.  */

	up_buf(password0_buf,&alt_ctx0,  password0_len);
	up_buf(salt_buf,&alt_ctx0,  salt_len);
	up_buf(password0_buf, &alt_ctx0,  password0_len);



	sha512_final(&alt_ctx0);

	/* Add for any character in the key one byte of the alternate sum.  */

    transmit(alt_ctx0.state, tmp_state);
    int cnt;


    up_buf( tmp_state,&ctx0, password0_len);

	for (cnt = password0_len; cnt > 0; cnt >>= 1) {
#pragma HLS loop_tripcount min=2 max=32
		if ((cnt & 1) != 0){
		    transmit(alt_ctx0.state, tmp_state);
		    sha512_update(&ctx0, tmp_state, 64);
			//sha512_update(&ctx0, (char *) alt_ctx0.state, 64);
		}
		else
			sha512_update(&ctx0, password0_buf, password0_len);
	}

	sha512_final(&ctx0);



	sha512_init(&p_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < password0_len; cnt++) {
#pragma HLS loop_tripcount min=1 max=32
		sha512_update(&p_bytes0, password0_buf, password0_len);
	}

	/* Finish the state.  */
	sha512_final(&p_bytes0);

	/* Start computation of S byte sequence.  */
//#ifdef FOUR_STAGE
	sha512_init(&s_bytes0);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < 16 + ((unsigned char*) ctx0.state)[0]; cnt++) {
#pragma HLS loop_tripcount min=1 max=256
		sha512_update(&s_bytes0, salt_buf, salt_len);
	}

	/* Finish the state.  */
	sha512_final(&s_bytes0);

#ifdef WPC
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
#endif

	for(i = 0; i < 8; i++){
		output->ctx0[i] = ctx0.state[i];
	}

	for(i = 0; i < 8; i++){
		output->p_bytes0[i] = p_bytes0.state[i];
	}
	for(i = 0; i < 8; i++){
		output->s_bytes0[i] = s_bytes0.state[i];
	}

}
