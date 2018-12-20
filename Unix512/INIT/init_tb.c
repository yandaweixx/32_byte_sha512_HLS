#include<stdio.h>
#include <string.h>
#include "init_top.h"
#define HASH_SIZE_SHA512UNIX      86
#define DIGEST_SIZE_SHA512         8 * 8
const char BASE64B_TAB[64] =
{
  '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

extern void sha512unix_decode ( char digest[DIGEST_SIZE_SHA512],  char buf[HASH_SIZE_SHA512UNIX]);
void hashing_01800_part1(char pwd[MAX_PASSW],int password0_len, int salt_len, char salt[MAX_SALT] , uint64_t output[4][16]);
extern int compare_digest_sha512 (const void *p1, const void *p2);

int base64b_char2int (char c)
{
  char *p = strchr (BASE64B_TAB, c);

  if (p == NULL) return (-1);

  return (p - BASE64B_TAB);
}

void sha512unix_decode ( char digest[DIGEST_SIZE_SHA512],  char buf[HASH_SIZE_SHA512UNIX])
{

  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[21] = (l >>  8) & 0xff;
  digest[42] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[ 1] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[ 2] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[24] = (l >>  8) & 0xff;
  digest[45] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[ 4] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[ 5] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[27] = (l >>  8) & 0xff;
  digest[48] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[ 7] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[30] = (l >>  8) & 0xff;
  digest[51] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;
  l |= base64b_char2int (buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[10] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[44]) <<  0;
  l |= base64b_char2int (buf[45]) <<  6;
  l |= base64b_char2int (buf[46]) << 12;
  l |= base64b_char2int (buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >>  8) & 0xff;
  digest[32] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[48]) <<  0;
  l |= base64b_char2int (buf[49]) <<  6;
  l |= base64b_char2int (buf[50]) << 12;
  l |= base64b_char2int (buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >>  8) & 0xff;
  digest[54] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[52]) <<  0;
  l |= base64b_char2int (buf[53]) <<  6;
  l |= base64b_char2int (buf[54]) << 12;
  l |= base64b_char2int (buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[56]) <<  0;
  l |= base64b_char2int (buf[57]) <<  6;
  l |= base64b_char2int (buf[58]) << 12;
  l |= base64b_char2int (buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >>  8) & 0xff;
  digest[35] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[60]) <<  0;
  l |= base64b_char2int (buf[61]) <<  6;
  l |= base64b_char2int (buf[62]) << 12;
  l |= base64b_char2int (buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >>  8) & 0xff;
  digest[57] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[64]) <<  0;
  l |= base64b_char2int (buf[65]) <<  6;
  l |= base64b_char2int (buf[66]) << 12;
  l |= base64b_char2int (buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[16] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[68]) <<  0;
  l |= base64b_char2int (buf[69]) <<  6;
  l |= base64b_char2int (buf[70]) << 12;
  l |= base64b_char2int (buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >>  8) & 0xff;
  digest[38] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[72]) <<  0;
  l |= base64b_char2int (buf[73]) <<  6;
  l |= base64b_char2int (buf[74]) << 12;
  l |= base64b_char2int (buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >>  8) & 0xff;
  digest[60] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[76]) <<  0;
  l |= base64b_char2int (buf[77]) <<  6;
  l |= base64b_char2int (buf[78]) << 12;
  l |= base64b_char2int (buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[19] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[80]) <<  0;
  l |= base64b_char2int (buf[81]) <<  6;
  l |= base64b_char2int (buf[82]) << 12;
  l |= base64b_char2int (buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >>  8) & 0xff;
  digest[41] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[84]) <<  0;
  l |= base64b_char2int (buf[85]) <<  6;

  digest[63] = (l >>  0) & 0xff;
}


/*$6$loBVOjNs$GK/LLDNzB0n84yaBAwa8kVk/atvmNviidaJcM.UfgQUV.RXYt/oG0543UJIeLbIQnEAuJ38BgJw3Zys1aoNTf0*/
int main(int argc, char **argv){
	int match = 0;
	 char * codes ="GK/LLDNzB0n84yaBAwa8kVk/atvmNviidaJcM.UfgQUV.RXYt/oG0543UJIeLbIQnEAuJ38BgJw3Zys1aoNTf0" ;
	digest_t digest_target;

	sha512unix_decode ((char *)digest_target.buf64, codes);
	//plain_t *in;
	fifo_midel output;
	//&in->buf8 = "123456";
	//in->len = strlen("123456");
	hashing_01800_part1("123456",strlen("123456"), strlen("loBVOjNs"), "loBVOjNs" , &output);
	//match = compare_digest_sha512(&digest,&digest_target);
	return 0;
}
