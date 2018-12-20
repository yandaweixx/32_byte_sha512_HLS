#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "sha256.h"

int main(void) {
    unsigned char digest[64];
    int i, j, errors;

   struct {
        const unsigned char *teststring;
        unsigned unsigned char digest512[64];
    } tests[] = {
        { "abc", {
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        } },
        { "abcdefghabcdefghabcdefghabcdefgh", {
        		//74ca7090 41b387c4 b8d4 7ace62a0 240c 594f13eb02 565ccb
        		//0c969c 39d2e91caa 20b9d7 7b3e ea fe cd d6 b1 c4 06 e8 95 2c de
        		//be 43 42 d1 eb fe 3e a1 49 43 2b 08 10 00 ac 1d
            0x74, 0xca, 0x70, 0x90, 0x41, 0xb3, 0x87, 0xc4,
            0xb8, 0xd4, 0x7a, 0xce, 0x62, 0xa0, 0x24, 0x0c,
            0x59, 0x4f, 0x13, 0xeb, 0x02, 0x56, 0x5c, 0xcb,
            0x0c, 0x96, 0x9c, 0x39, 0xd2, 0xe9, 0x1c, 0xaa,
            0x20, 0xb9, 0xd7, 0x7b, 0x3e, 0xea, 0xfe, 0xcd,
            0xd6, 0xb1, 0xc4, 0x06, 0xe8, 0x95, 0x2c, 0xde,
            0xbe, 0x43, 0x42, 0xd1, 0xeb, 0xfe, 0x3e, 0xa1,
            0x49, 0x43, 0x2b, 0x08, 0x10, 0x00, 0xac, 0x1d,
        } },
      /*  { "0000", {
        		//74ca7090 41b387c4 b8d4 7ace62a0 240c 594f13eb02 565ccb
        		//0c969c 39d2e91caa 20b9d7 7b3e ea fe cd d6 b1 c4 06 e8 95 2c de
        		//be 43 42 d1 eb fe 3e a1 49 43 2b 08 10 00 ac 1d
            0x74, 0xca, 0x70, 0x90, 0x41, 0xb3, 0x87, 0xc4,
            0xb8, 0xd4, 0x7a, 0xce, 0x62, 0xa0, 0x24, 0x0c,
            0x59, 0x4f, 0x13, 0xeb, 0x02, 0x56, 0x5c, 0xcb,
            0x0c, 0x96, 0x9c, 0x39, 0xd2, 0xe9, 0x1c, 0xaa,
            0x20, 0xb9, 0xd7, 0x7b, 0x3e, 0xea, 0xfe, 0xcd,
            0xd6, 0xb1, 0xc4, 0x06, 0xe8, 0x95, 0x2c, 0xde,
            0xbe, 0x43, 0x42, 0xd1, 0xeb, 0xfe, 0x3e, 0xa1,
            0x49, 0x43, 0x2b, 0x08, 0x10, 0x00, 0xac, 0x1d,
        } },
        { "0001", {
        		//74ca7090 41b387c4 b8d4 7ace62a0 240c 594f13eb02 565ccb
        		//0c969c 39d2e91caa 20b9d7 7b3e ea fe cd d6 b1 c4 06 e8 95 2c de
        		//be 43 42 d1 eb fe 3e a1 49 43 2b 08 10 00 ac 1d
            0x74, 0xca, 0x70, 0x90, 0x41, 0xb3, 0x87, 0xc4,
            0xb8, 0xd4, 0x7a, 0xce, 0x62, 0xa0, 0x24, 0x0c,
            0x59, 0x4f, 0x13, 0xeb, 0x02, 0x56, 0x5c, 0xcb,
            0x0c, 0x96, 0x9c, 0x39, 0xd2, 0xe9, 0x1c, 0xaa,
            0x20, 0xb9, 0xd7, 0x7b, 0x3e, 0xea, 0xfe, 0xcd,
            0xd6, 0xb1, 0xc4, 0x06, 0xe8, 0x95, 0x2c, 0xde,
            0xbe, 0x43, 0x42, 0xd1, 0xeb, 0xfe, 0x3e, 0xa1,
            0x49, 0x43, 0x2b, 0x08, 0x10, 0x00, 0xac, 0x1d,
        } },*/

    };

   /* struct {
           const unsigned char *teststring;
       } tests[] = {
           { "abc", },
           { "abcdefghabcdefghhcdefghabcdefgh", },
		   { "abcdefghabddefghabcdefghscdefgh", },
		   { "abcdefghabcdefdhabsfghabcdefgh", },
		   { "abcdefghabcdfdabcdefghabcdefgh", },
		   { "abcdefghabddefghabcdefghabcdefgh", },
		   { "abfdefghabcdefghafdefghabcdefgh", },
		   { "abcdefghdbcdefghabcdpcdefgh", },
		   { "abcdefghadughabcdefghabcdefgh", },
		   { "abcdefgdbcdefghabcdefghfcdefgh", },
		   { "abcdedfghabcdefghabcdyed", },
		   { "abcdevhabcdefghabcdefghabcwfgh", },
		   { "abcdefghabcdefghabcdefghabcdefgh", },
		   { "abcdefghabcdefghabcdefqdefgh", },
		   { "abcdefghabcdefghabcdeubcdefgh", },
		   { "abcdefgscdefgscdefghabcdefgh", },
		   { "abcdefghasfdefghabcdefgdcdefgh", },
		   { "abcdffghabcdefghabcdefgh", },
		   { "abcscdefghabcdefghycdefgh", },
		   { "abcscdefghabcdefghabcdefgh", },
		   { "abcscdefgrrhrebcdefgh", },
		   { "abcscdefghabcdefghabcdefgh", },
		   { "abcscdefghabcdedbcdefgh", },
		   { "abcscdefghabcdefghabcdefgh", },
		   { "abcscdefghabudefgh", },
		   { "abcscdefghabcdefsabcdefgh", },
		   { "abcscdefgsabcdefgh", },
		   { "abdcdefghabcdefghabcjefgh", },
		   { "abcscdefghscufgsbcdefgh", },
		   { "abcscdefsdabcufghabcdefgh", },
		   { "abcssefghabcufghscdefgh", },
		   { "0000", },
		   { "0001", },

       };*/

    errors = 0;
    p_in test_tmp[64];
    d_out digest_tmp;

    for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
        if (tests[i].teststring) {
        	memset(test_tmp[i].passwd,0,64);
        	memcpy(test_tmp[i].passwd, tests[i].teststring, strlen(tests[i].teststring));
        	//test_tmp.passwd = tests[i].teststring;
        	//test_tmp[i].len = (unsigned char)strlen(tests[i].teststring) ;
        	SHA512_Simple(&test_tmp[i], (unsigned char)strlen(tests[i].teststring),&digest_tmp);
        	memcpy(digest,digest_tmp.digest,64);

        }

       for (j = 0; j < 64; j++) {
            if (digest[j] != tests[i].digest512[j]) {
                fprintf(stderr,
                        "\"%s\" digest512 byte %d should be 0x%02x, is 0x%02x\n",
                        tests[i].teststring, j, tests[i].digest512[j],
                        digest[j]);
                errors++;
            }
        }

    }

    printf("%d errors\n", errors);

    return errors;
   // return 0;

}
