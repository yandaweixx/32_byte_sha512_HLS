#include"top_rar5.hpp"
u32x swap32(const u32x v)
{
	return ((v >> 24) & 0x000000ff)
		| ((v >> 8) & 0x0000ff00)
		| ((v << 8) & 0x00ff0000)
		| ((v << 24) & 0xff000000);
}

u8 hex_convert(const u8 c)
{
	return (c & 15) + (c >> 6) * 9;
}

u32 hex_to_u32(const u8 hex[8])
{
	u32 v = 0;

	v |= ((u32)hex_convert(hex[7])) << 0;
	v |= ((u32)hex_convert(hex[6])) << 4;
	v |= ((u32)hex_convert(hex[5])) << 8;
	v |= ((u32)hex_convert(hex[4])) << 12;
	v |= ((u32)hex_convert(hex[3])) << 16;
	v |= ((u32)hex_convert(hex[2])) << 20;
	v |= ((u32)hex_convert(hex[1])) << 24;
	v |= ((u32)hex_convert(hex[0])) << 28;

	return (v);
}
int rar5_parse_hash(char* hash, uint32_t hash_len, uint32_t salt[4], uint32_t* iter, uint32_t pwd_check_val[2])
{
	if ((hash_len < DISPLAY_LEN_MIN_13000) || (hash_len > DISPLAY_LEN_MAX_13000)) return (PARSER_GLOBAL_LENGTH);
	if (memcmp(SIGNATURE_RAR5, hash, 1 + 4 + 1)) return (PARSER_SIGNATURE_UNMATCHED);

	char *param0_pos = hash + 1 + 4 + 1;
	char *param1_pos = strchr(param0_pos, '$');
	if (param1_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);
	u32 param0_len = param1_pos - param0_pos;
	param1_pos++;
	char *param2_pos = strchr(param1_pos, '$');
	if (param2_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);
	u32 param1_len = param2_pos - param1_pos;
	param2_pos++;
	char *param3_pos = strchr(param2_pos, '$');
	if (param3_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);
	u32 param2_len = param3_pos - param2_pos;
	param3_pos++;
	char *param4_pos = strchr(param3_pos, '$');
	if (param4_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);
	u32 param3_len = param4_pos - param3_pos;
	param4_pos++;
	char *param5_pos = strchr(param4_pos, '$');
	if (param5_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);
	u32 param4_len = param5_pos - param4_pos;
	param5_pos++;
	u32 param5_len = hash_len - 1 - 4 - 1 - param0_len - 1 - param1_len - 1 - param2_len - 1 - param3_len - 1 - param4_len - 1;

	char *salt_buf = param1_pos;
	//char *iv       = param3_pos;
	char *pswcheck = param5_pos;

	const u32 salt_len = atoi(param0_pos);
	const u32 iterations = atoi(param2_pos);
	const u32 pswcheck_len = atoi(param4_pos);

	/**
	* verify some data
	*/

	if (param1_len != 32) return (PARSER_SALT_VALUE);
	if (param3_len != 32) return (PARSER_SALT_VALUE);
	if (param5_len != 16) return (PARSER_SALT_VALUE);

	if (salt_len != 16) return (PARSER_SALT_VALUE);
	if (iterations == 0) return (PARSER_SALT_VALUE);
	if (pswcheck_len != 8) return (PARSER_SALT_VALUE);

	/**
	* store data
	*/

	salt[0] = hex_to_u32((const u8 *)&salt_buf[0]);
	salt[1] = hex_to_u32((const u8 *)&salt_buf[8]);
	salt[2] = hex_to_u32((const u8 *)&salt_buf[16]);
	salt[3] = hex_to_u32((const u8 *)&salt_buf[24]);
	//  printf("salt:%u,%u,%u,%u\n",salt[0],salt[1],salt[2],salt[3]);
	*iter = ((1u << iterations) + 32) - 1;

	// rar5->iv[0] = hex_to_u32 ((const u8 *) &iv[ 0]);
	// rar5->iv[1] = hex_to_u32 ((const u8 *) &iv[ 8]);
	// rar5->iv[2] = hex_to_u32 ((const u8 *) &iv[16]);
	// rar5->iv[3] = hex_to_u32 ((const u8 *) &iv[24]);

	// salt->salt_len = 16;

	// salt->salt_sign[0] = iterations;

	// salt->salt_iter = ((1u << iterations) + 32) - 1;

	/**
	* digest buf
	*/

	pwd_check_val[0] = hex_to_u32((const u8 *)&pswcheck[0]);
	pwd_check_val[1] = hex_to_u32((const u8 *)&pswcheck[8]);
	//  printf("pwd_check_val:%u,%u\n",pwd_check_val[0],pwd_check_val[1]);
	return (PARSER_OK);
}
int main(int argc, char** argv){

	int i,j;
	int erro =0 ;
	int tmp_len;

	hls::stream<pwd_t> pwd;
	hls::stream<salt_t> salt;
	hls::stream<digest_t> digest;
	hls::stream<digest_t> golden_digest;

	//hls::stream<int> hash_len;

	pwd_t tmp_pwd;
	uint32_t iter[NN] = { 0 };
	salt_t tmp_salt;
	digest_t tmp_golden_digest;

	char hashlist[NUM3] = "$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754";

	for(i = 0; i < NN;i++){
		tmp_len = strlen("$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754");
		//hash_len.write(tmp_len);
		memset(tmp_pwd.pwd, 0, 16*sizeof(uint32_t));
		memcpy(tmp_pwd.pwd, "hashcat", strlen("hashcat"));
		for (int k = 0; k<16; ++k)
		{
			tmp_pwd.pwd[k] = swap32(tmp_pwd.pwd[k]);
		}
		pwd.write(tmp_pwd);
		rar5_parse_hash(hashlist, tmp_len, tmp_salt.salt_buf, iter + i, tmp_golden_digest.digest);

		salt.write(tmp_salt);
		golden_digest.write(tmp_golden_digest);

	}
	top_rar5( pwd,  salt,  digest);

	for(i = 0 ; i < NN; i++){
		if(memcmp(digest.read().digest,golden_digest.read().digest,2))
			erro++;
	}
	return erro;







}
