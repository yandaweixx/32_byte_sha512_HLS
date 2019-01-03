#include "top_rar5.hpp"

void sha256_process_ini2(uint32_t state[8], const uint32_t data[16], uint32_t ret[8])
{
	uint32_t temp1, temp2;
	uint32_t W[64];
	uint32_t A[8];
	unsigned int i;

	for (i = 0; i < 8; i++)
		A[i] = state[i];
	for (i = 0; i < 16; i++)
		W[i] = data[i];
	for (i = 0; i < 16; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i + 0], K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i + 1], K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i + 2], K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i + 3], K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i + 4], K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i + 5], K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i + 6], K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i + 7], K[i + 7]);
	}

	for (i = 16; i < 64; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i + 0), K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i + 1), K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i + 2), K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i + 3), K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i + 4), K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i + 5), K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i + 6), K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i + 7), K[i + 7]);
	}
	//***#endif /* MBEDTLS_SHA256_SMALLER */

	for (i = 0; i < 8; i++)
		ret[i] = state[i] + A[i];
}

void sha256_process_ini1(uint32_t state[8],  uint32_t *data, uint32_t ret[8])
{
	uint32_t temp1, temp2;
	uint32_t W[64];
	uint32_t A[8];
	unsigned int i;

	for (i = 0; i < 8; i++)
		A[i] = state[i];
	for (i = 0; i < 4; i++)
		W[i] = data[i];
	for (i = 4; i < 16; i++)
		W[i] = INT1[i - 4];
	for (i = 0; i < 16; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i + 0], K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i + 1], K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i + 2], K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i + 3], K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i + 4], K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i + 5], K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i + 6], K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i + 7], K[i + 7]);
	}

	for (i = 16; i < 64; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i + 0), K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i + 1), K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i + 2), K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i + 3), K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i + 4), K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i + 5), K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i + 6), K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i + 7), K[i + 7]);
	}
	//***#endif /* MBEDTLS_SHA256_SMALLER */

	for (i = 0; i < 8; i++)
		ret[i] = state[i] + A[i];
}


void buffer_sha256(u32 in1[8], u32 in2[8],u32 out1[8], u32 out2[8])
{
#pragma HLS LATENCY min=1
    int j=0;
    int buffer1[8], buffer2[8];
#pragma HLS ARRAY_PARTITION variable=buffer2 complete dim=1
#pragma HLS ARRAY_PARTITION variable=buffer1 complete dim=1
    for (j=0;j<8;j++)
    {
        buffer1[j]=in1[j];
        buffer2[j]=in2[j];
    }
    for (j=0;j<8;j++)
    {
        out1[j]=buffer1[j];
        out2[j]=buffer2[j];
    }
}

void sha256_process(uint32_t in1[8], uint32_t in2[8], uint32_t ret[8])
{
	#pragma HLS ALLOCATION instances=buffer_sha256 limit=1 function
	u32 data[8], state[8];
	uint32_t temp1, temp2;
	uint32_t W[64];
	uint32_t A[8];

	buffer_sha256(in1,in2,state,data);
	unsigned int i;

	for (i = 0; i < 8; i++)
		A[i] = state[i];
	for (i = 0; i < 8; i++)
		W[i] = data[i];
	for (i = 8; i < 16; i++)
		W[i] = INT[i - 8];
	for (i = 0; i < 16; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i + 0], K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i + 1], K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i + 2], K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i + 3], K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i + 4], K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i + 5], K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i + 6], K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i + 7], K[i + 7]);
	}

	for (i = 16; i < 64; i += 8)
	{
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i + 0), K[i + 0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i + 1), K[i + 1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i + 2), K[i + 2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i + 3), K[i + 3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i + 4), K[i + 4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i + 5), K[i + 5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i + 6), K[i + 6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i + 7), K[i + 7]);
	}
	//***#endif /* MBEDTLS_SHA256_SMALLER */

	for (i = 0; i < 8; i++)
		ret[i] = state[i] + A[i];
}

uint32_t Tmem[N * 4][8];
void Tmem_get(uint32_t T[8])
{
#pragma HLS ARRAY_PARTITION variable=Tmem complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		T[j] = Tmem[i][j];
	i=i+2;
	if (i == N*4)    //  RESET the address counter
		i=0;
}

uint32_t Tmemcopy[N * 4][8];
void Tmemcopy_get(uint32_t T[8])
{
#pragma HLS ARRAY_PARTITION variable=Tmemcopy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		T[j] = Tmemcopy[i][j];
	i=i+2;
	if (i == N*4+1)    //  RESET the address counter
        i=1;
}

uint32_t out1mem[N][8];
void Out1write(uint32_t stateIn[8])
{
#pragma HLS PIPELINE II=2
#pragma HLS ARRAY_PARTITION variable=out1mem complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		out1mem[i][j] ^= stateIn[j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t out1mem_copy[N][8];
void Out1write_copy(uint32_t stateIn[8])
{
#pragma HLS PIPELINE II=2
#pragma HLS ARRAY_PARTITION variable=out1mem_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		out1mem_copy[i][j] ^= stateIn[j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

uint32_t out2mem[N][8];
void Out2write(uint32_t stateIn[8])
{
#pragma HLS PIPELINE II=2
#pragma HLS ARRAY_PARTITION variable=out2mem complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		out2mem[i][j] ^= stateIn[j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t out2mem_copy[N][8];
void Out2write_copy(uint32_t stateIn[8])
{
#pragma HLS PIPELINE II=2
#pragma HLS ARRAY_PARTITION variable=out2mem_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		out2mem_copy[i][j] ^= stateIn[j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

uint32_t state0[N][8];
void state0_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state0 complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state0[i][j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t state1[N][8];
void state1_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state1 complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state1[i][j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t state2[N][8];
void state2_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state2 complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state2[i][j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t state3[N][8];
void state3_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state3 complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state3[i][j];
	i = i + 2;
	if (i == N)
		i = 0;
}

uint32_t state0_copy[N][8];
void state0_copy_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state0_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state0_copy[i][j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

uint32_t state1_copy[N][8];
void state1_copy_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state1_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state1_copy[i][j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

uint32_t state2_copy[N][8];
void state2_copy_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state2_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state2_copy[i][j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

uint32_t state3_copy[N][8];
void state3_copy_get(uint32_t state_temp[8])
{
#pragma HLS ARRAY_PARTITION variable=state3_copy complete dim=2
	static int i = 1;
	int j;
	for (j = 0; j < 8; j++)
		state_temp[j] = state3_copy[i][j];
	i = i + 2;
	if (i == N + 1)
		i = 1;
}

void state0_store(uint32_t hash_out[8])
{
#pragma HLS ARRAY_PARTITION variable=state0 complete dim=2
#pragma HLS ARRAY_PARTITION variable=state0_copy complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
	{
		state0[i][j] = hash_out[j];
		state0_copy[i][j] = hash_out[j];
	}
	i = i + 1;
	if (i == N)
		i = 0;
}

void state1_store(uint32_t hash_out[8])
{
#pragma HLS ARRAY_PARTITION variable=state1 complete dim=2
#pragma HLS ARRAY_PARTITION variable=state1_copy complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
	{
		state1[i][j] = hash_out[j];
		state1_copy[i][j] = hash_out[j];
	}
	i = i + 1;
	if (i == N)
		i = 0;
}

void state2_store(uint32_t hash_out[8])
{
#pragma HLS ARRAY_PARTITION variable=state2 complete dim=2
#pragma HLS ARRAY_PARTITION variable=state2_copy complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
	{
		state2[i][j] = hash_out[j];
		state2_copy[i][j] = hash_out[j];
	}
	i = i + 1;
	if (i == N)
		i = 0;
}

void state3_store(uint32_t hash_out[8])
{
#pragma HLS ARRAY_PARTITION variable=state3 complete dim=2
#pragma HLS ARRAY_PARTITION variable=state3_copy complete dim=2
	static int i = 0;
	int j;
	for (j = 0; j < 8; j++)
	{
		state3[i][j] = hash_out[j];
		state3_copy[i][j] = hash_out[j];
	}
	i = i + 1;
	if (i == N)
		i = 0;
}

void sha256_test(uint32_t H[N * 2][8], uint32_t T_input[N * 4][8], uint32_t xcheck_val[N * 2][2])
{

#pragma HLS ALLOCATION instances=sha256_process limit=1 function
	int i, j, k;
	uint32_t  Ttemp[8], Ttemp_copy[8];
#pragma HLS ARRAY_PARTITION variable=Ttemp_copy complete dim=1
#pragma HLS ARRAY_PARTITION variable=Ttemp complete dim=1
	uint32_t  StateTemp[8], StateTemp_copy[8];
#pragma HLS ARRAY_PARTITION variable=StateTemp_copy complete dim=1
#pragma HLS ARRAY_PARTITION variable=StateTemp complete dim=1
	uint32_t  hashout[8];
#pragma HLS ARRAY_PARTITION variable=hashout complete dim=1


	for (i = 0; i < N; i++)     // save the initial data from the interface to global memory
	{
		for (j = 0; j < 8; j++)
		{
			state0[i][j] = H[i][j];                //set1 state
			state0_copy[i][j] = H[i][j];

			state1[i][j] = H[i + N][j];             //set2 state
			state1_copy[i][j] = H[i + N][j];

			out1mem[i][j] = H[i][j];
			out1mem_copy[i][j] = H[i][j];
			out2mem[i][j] = H[i + N][j];
			out2mem_copy[i][j] = H[i + N][j];

			Tmem[i][j] = T_input[i][j];
			Tmem[i + N][j] = T_input[i + N][j];
			Tmem[i + N * 2][j] = T_input[i + N * 2][j];
			Tmem[i + N * 3][j] = T_input[i + N * 3][j];

			Tmemcopy[i][j] = T_input[i][j];
			Tmemcopy[i + N][j] = T_input[i + N][j];
			Tmemcopy[i + N * 2][j] = T_input[i + N * 2][j];
			Tmemcopy[i + N * 3][j] = T_input[i + N * 3][j];
		}
	}

	for (k = 0; k < 32799*2; k++)
	{
#pragma HLS PIPELINE II=213
		if(k%2==0)
		{
		for (i = 0; i < N; i = i + 2)
		{
			Tmem_get(Ttemp);
			Tmemcopy_get(Ttemp_copy);   //get T input  from BRAM copy
			state0_get(StateTemp);
			state0_copy_get(StateTemp_copy);   // get state input from state0_copy
			sha256_process(Ttemp, StateTemp, hashout);
			state2_store(hashout);
			sha256_process(Ttemp_copy, StateTemp_copy, hashout);
			state2_store(hashout); // store the hash state2 memory
		}

		for (i = 0; i < N; i = i + 2)
		{
			Tmem_get(Ttemp);
			Tmemcopy_get(Ttemp_copy);   //get T input  from BRAM copy
			state1_get(StateTemp);
			state1_copy_get(StateTemp_copy);   // get state input from state1_copy
			sha256_process(Ttemp, StateTemp, hashout);
			state3_store(hashout);
			sha256_process(Ttemp_copy, StateTemp_copy, hashout);
			state3_store(hashout); // store the hash state3 memory
		}
		}
		else
		{
		for (i = 0; i < N; i = i + 2)
		{
			Tmem_get(Ttemp);
			Tmemcopy_get(Ttemp_copy);   //get T input  from BRAM copy
			state2_get(StateTemp);
			state2_copy_get(StateTemp_copy);   // get state input from state0_copy
			sha256_process(Ttemp, StateTemp, hashout);
			Out1write(hashout);
			state0_store(hashout);
			sha256_process(Ttemp_copy, StateTemp_copy, hashout);
			Out1write_copy(hashout);
			state0_store(hashout);
		}

		for (i = 0; i < N; i = i + 2)
		{
			Tmem_get(Ttemp);
			Tmemcopy_get(Ttemp_copy);   //get T input  from BRAM copy
			state3_get(StateTemp);
			state3_copy_get(StateTemp_copy);   // get state input from state1_copy
			sha256_process(Ttemp, StateTemp, hashout);
			Out2write(hashout);
			state1_store(hashout);
			sha256_process(Ttemp_copy, StateTemp_copy, hashout);
			Out2write_copy(hashout);
			state1_store(hashout);
		}
		}

	}

	for (i = 0; i < N; i++)
	{
		if (i % 2 == 0)
		{
			xcheck_val[i][0] = out1mem[i][0] ^ out1mem[i][2] ^ out1mem[i][4] ^ out1mem[i][6];
			xcheck_val[i][1] = out1mem[i][1] ^ out1mem[i][3] ^ out1mem[i][5] ^ out1mem[i][7];

			xcheck_val[i + N][0] = out2mem[i][0] ^ out2mem[i][2] ^ out2mem[i][4] ^ out2mem[i][6];
			xcheck_val[i + N][1] = out2mem[i][1] ^ out2mem[i][3] ^ out2mem[i][5] ^ out2mem[i][7];
		}
		else
		{
			xcheck_val[i][0] = out1mem_copy[i][0] ^ out1mem_copy[i][2] ^ out1mem_copy[i][4] ^ out1mem_copy[i][6];
			xcheck_val[i][1] = out1mem_copy[i][1] ^ out1mem_copy[i][3] ^ out1mem_copy[i][5] ^ out1mem_copy[i][7];

			xcheck_val[i + N][0] = out2mem_copy[i][0] ^ out2mem_copy[i][2] ^ out2mem_copy[i][4] ^ out2mem_copy[i][6];
			xcheck_val[i + N][1] = out2mem_copy[i][1] ^ out2mem_copy[i][3] ^ out2mem_copy[i][5] ^ out2mem_copy[i][7];
		}
	}

}

void top_rar5(hls::stream<pwd_t> &pwd, hls::stream<salt_t> &salt_buf, hls::stream<digest_t> &digest){
	int len,i,j;
//	TIMER_TYPE start_t, end_t;
	uint32_t IV[8] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

	uint32_t si[NN][16] = { 0 };
	uint32_t so[NN][16] = { 0 };
	uint32_t T1[NN][8] = { 0 };
	uint32_t T2[NN][8] = { 0 };
	uint32_t T[NN + NN][8] = { 0 };
	uint32_t xcheck_val[NN][2] = { 0 };
	uint32_t temp[NN][8] = { 0 };
	uint32_t out[NN][8] = { 0 };
#pragma HLS ARRAY_PARTITION variable=si complete dim=2
#pragma HLS ARRAY_PARTITION variable=so complete dim=2
#pragma HLS ARRAY_PARTITION variable=T1 complete dim=2
#pragma HLS ARRAY_PARTITION variable=T2 complete dim=2
#pragma HLS ARRAY_PARTITION variable=T complete dim=2
#pragma HLS ARRAY_PARTITION variable=xcheck_val complete dim=2
#pragma HLS ARRAY_PARTITION variable=temp complete dim=2
#pragma HLS ARRAY_PARTITION variable=out complete dim=2
	//uint32_t inter_hash_len[NN] = { 0 };

	pwd_t inter_pwd;

	salt_t inter_salt_buf;

	//uint32_t iter[NN] = { 0 };
	digest_t pwd_check_val;
	int flag = 0;

//	TIMER_NOW(start_t);

	for (i = 0; i < NN; ++i)
	{
		inter_pwd = pwd.read();
		for ( j = 0; j < 16; ++j)
		{
			si[i][j] = inter_pwd.pwd[j] ^ 0x36363636;
			so[i][j] = si[i][j] ^ 0x6a6a6a6a;
			//printf("!!!!si:%u\n",si[0][d]);
			//	printf("@@@@so:%u\n",so[0][d]);
		}
			/*	printf("si:%u,%u,\n",si[0][0],si[0][1]);
				printf("so:%u,%u,\n",so[0][0],so[0][1]);*/
	}

	for ( i = 0; i < NN; ++i)
	{
		sha256_process_ini2(IV, *(si + i), *(T1 + i));
		sha256_process_ini2(IV, *(so + i), *(T2 + i));
	}
		//printf("T:%u,%u,%u,%u,\n",T1[0][0],T1[0][1],T2[0][0],T2[0][1]);

	for ( i = 0; i < NN; i++)
	{
		inter_salt_buf = salt_buf.read();
		sha256_process_ini1(*(T1 + i), inter_salt_buf.salt_buf, *(temp + i));
		//H[i][j] = out[j];
		sha256_process(*(T2 + i), *(temp + i), *(temp + i));
	}
		//printf("temp:%u,%u,\n",temp[0][0],temp[0][1]);
	//
		//printf("T1:%u,%u,\n",T1[2][0],T1[2][1]);
		//printf("T2:%u,%u,\n",T2[2][0],T2[2][1]);

	//	for(int s = 0; s < NN+NN; s+=2)
	//	{
	//		for(int t = 0; t < 8; t++)
	//		{
	//			T[s][t] = T1[s/2][t];
	//			T[s+1][t] = T2[s/2][t];
	//		}
	//	}

	for ( i = 0; i < NN; i++)
	{
		for ( j = 0; j < 8; j++)
		{
			T[i][j] = T1[i][j];
			T[i + NN][j] = T2[i][j];
		}
	}
	sha256_test(temp, T, xcheck_val /*,out*/);

	for(i = 0; i < NN; i++){
		for(j= 0; j < 2; j++)
			pwd_check_val.digest[j] =   xcheck_val[i][j];
		digest.write(pwd_check_val);
	}
}
