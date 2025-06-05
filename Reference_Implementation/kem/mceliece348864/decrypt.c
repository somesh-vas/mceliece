/*
  This file is for Niederreiter decryption
*/

#include <stdio.h>
#include "decrypt.h"

#include "params.h"
#include "benes.h"
#include "util.h"
#include "synd.h"
#include "root.h"
#include "gf.h"
#include "bm.h"
#include "nist/cpucycles.h"

/* Niederreiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         c, ciphertext */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
int decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *c)
{
	int i, w = 0; 
	uint16_t check;	

	unsigned char r[ SYS_N/8 ];

	gf g[ SYS_T+1 ];
	gf L[ SYS_N ];

	gf s[ SYS_T*2 ];
	gf s_cmp[ SYS_T*2 ];
	gf locator[ SYS_T+1 ];
	gf images[ SYS_N ];

	gf t;

	//#######################################
	uint64_t start_cycles, end_cycles, total_cycles = 0;
    	FILE *output_file;
    	output_file = fopen("cpucycles/support_gen.txt", "a");
    	// start_cycles = rdtsc();
	//#######################################

	//

	for (i = 0; i < SYND_BYTES; i++)       r[i] = c[i];
	for (i = SYND_BYTES; i < SYS_N/8; i++) r[i] = 0;

	for (i = 0; i < SYS_T; i++) { g[i] = load_gf(sk); sk += 2; } g[ SYS_T ] = 1;
	
	start_cycles = rdtsc();
	support_gen(L, sk);
	end_cycles = rdtsc();
	total_cycles = (end_cycles - start_cycles);
	fprintf(output_file, "%lu\n", (unsigned long) total_cycles);	
	fclose(output_file);
	//#####################
	total_cycles = 0;
	start_cycles = rdtsc();
	FILE *output_file1;
    	output_file1 = fopen("cpucycles/synd.txt", "a");
	
	synd(s, g, L, r);

	end_cycles = rdtsc();
	total_cycles = (end_cycles - start_cycles);
	fprintf(output_file1, "%lu\n", (unsigned long) total_cycles);	
	fclose(output_file1);
	//#####################

	//#####################
	total_cycles = 0;
	start_cycles = rdtsc();
	FILE *output_file2;
    	output_file2 = fopen("cpucycles/bm.txt", "a");
	
	bm(locator, s);
	end_cycles = rdtsc();
	total_cycles = (end_cycles - start_cycles);
	fprintf(output_file2, "%lu\n", (unsigned long) total_cycles);	
	fclose(output_file2);

	//#####################
	total_cycles = 0;
	start_cycles = rdtsc();
	FILE *output_file3;
    	output_file3 = fopen("cpucycles/root.txt", "a");
	
	root(images, locator, L);

	end_cycles = rdtsc();
	total_cycles = (end_cycles - start_cycles);
	fprintf(output_file3, "%lu\n", (unsigned long) total_cycles);	
	fclose(output_file3);
	//
	
	for (i = 0; i < SYS_N/8; i++) 
		e[i] = 0;

	for (i = 0; i < SYS_N; i++)
	{
		t = gf_iszero(images[i]) & 1;

		e[ i/8 ] |= t << (i%8);
		w += t;

	}

#ifdef KAT
  {
    int k;
    printf("decrypt e: positions");
    for (k = 0;k < SYS_N;++k)
      if (e[k/8] & (1 << (k&7)))
        printf("~%d",k);
    printf("\n");
  }
#endif
	
	synd(s_cmp, g, L, e);

	//

	check = w;
	check ^= SYS_T;

	for (i = 0; i < SYS_T*2; i++)
		check |= s[i] ^ s_cmp[i]; 

	check -= 1;
	check >>= 15;

	return check ^ 1;
}

