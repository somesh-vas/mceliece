/*
   PQCgenKAT_kem.c
   Created by Bassham, Lawrence E (Fed) on 8/29/17.
   Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
   + mods from djb: see KATNOTES
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rng.h"
#include "crypto_kem.h"
//#include "stdint.h"
#include "cpucycles/cpucycles.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_CRYPTO_FAILURE  -4

void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

unsigned char entropy_input[48];
unsigned char seed[KATNUM][48];





int
main()
{
    FILE                *fp_req, *fp_rsp,*output_file;
    int                 ret_val;
    int i;
    unsigned char *ct = 0;
    unsigned char *ss = 0;
    unsigned char *ss1 = 0;
    unsigned char *pk = 0;
    unsigned char *sk = 0;
    
   uint64_t start_cycles, end_cycles, total_cycles = 0;
   
   output_file = fopen("cycles_result.txt", "a");
    if (output_file == NULL) {
        perror("Error opening file");
        return 1;
    }

    for (i=0; i<48; i++){
    	start_cycles = rdtsc();
        entropy_input[i] = i;
        end_cycles = rdtsc();
        total_cycles += (end_cycles - start_cycles);
        }
        // fprintf(output_file,"cpu cycles of the kat_kem.c functions\n\n");
        // fprintf(output_file,"******************************************************************\n");
        // fprintf(output_file,"This loop initializes the entropy_input array with values from 0 to 47. It appears to provide initial entropy data.\n");
        // fprintf(output_file, "Average CPU cycles per iteration: %lu\n", (unsigned long)(total_cycles / 48));
        // fprintf(output_file,"******************************************************************\n\n");
   
    

    
    //printf("Average CPU cycles per iteration: %llu\n", total_cycles/48);
    total_cycles = 0;
    start_cycles = rdtsc();
    randombytes_init(entropy_input, NULL, 256); 
    end_cycles = rdtsc();
    total_cycles = (end_cycles - start_cycles);
    // fprintf(output_file,"******************************************************************\n");
    // fprintf(output_file,"This function call initializes the random number generator using entropy_input as the initial entropy data. The NULL and 256 parameters indicate that no additional key data is provided and the size of the entropy data is 256 bytes.");
    // fprintf(output_file, "\nAverage CPU cycles of randombytes_init: %lu\n", (unsigned long)(total_cycles));
    // fprintf(output_file,"******************************************************************\n\n");
/*
    //void randombytes_init(void *buf, void *key, size_t size);
    //	buf: A pointer to the initial entropy data that will be used to seed the random number generator.
    //	key: A pointer to a secret key, which can be used to provide additional entropy for initialization 			(optional, can be set to NULL).	
    //	size: The size of the initial entropy buffer in bytes.		
*/

    total_cycles = 0;
    for (i=0; i<KATNUM; i++){
        start_cycles = rdtsc();
        randombytes(seed[i], 48);
        end_cycles = rdtsc();
        total_cycles += (end_cycles - start_cycles);
        }
        
        // fprintf(output_file,"******************************************************************\n");
        // fprintf(output_file,"This loop generates random bytes for each element of the seed array using the randombytes function.\n");
        // fprintf(output_file, "Average CPU cycles per iteration: %lu\n", (unsigned long)(total_cycles / 10));
        // fprintf(output_file,"******************************************************************\n\n");


    fp_req = fdopen(8, "w");
    if (!fp_req)
       return KAT_FILE_OPEN_ERROR;

    for (i=0; i<KATNUM; i++) {
        fprintf(fp_req, "count = %d\n", i);
        fprintBstr(fp_req, "seed = ", seed[i], 48);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "ct =\n");
        fprintf(fp_req, "ss =\n\n");
    }

    fp_rsp = fdopen(9, "w");
    if (!fp_rsp)
        return KAT_FILE_OPEN_ERROR;

    fprintf(fp_rsp, "# kem/%s\n\n", crypto_kem_PRIMITIVE);
	//############
	uint64_t enc_avg = 0, dec_avg = 0;
	//############	
    for (i=0; i<KATNUM; i++) {
        if (!ct) ct = malloc(crypto_kem_CIPHERTEXTBYTES);
        if (!ct) abort();
        if (!ss) ss = malloc(crypto_kem_BYTES);
        if (!ss) abort();
        if (!ss1) ss1 = malloc(crypto_kem_BYTES);
        if (!ss1) abort();
        if (!pk) pk = malloc(crypto_kem_PUBLICKEYBYTES);
        if (!pk) abort();
        if (!sk) sk = malloc(crypto_kem_SECRETKEYBYTES);
        if (!sk) abort();

        randombytes_init(seed[i], NULL, 256);

        fprintf(fp_rsp, "count = %d\n", i);
        fprintBstr(fp_rsp, "seed = ", seed[i], 48);
        //printf("testing");
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            //fprintf(stderr, "crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, crypto_kem_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, crypto_kem_SECRETKEYBYTES);
        //######################## encryption #################
        total_cycles = 0;
        start_cycles = rdtsc();
        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            //fprintf(stderr, "crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        end_cycles = rdtsc();
        enc_avg += (end_cycles - start_cycles);
        
        
       

        //####################################################
        fprintBstr(fp_rsp, "ct = ", ct, crypto_kem_CIPHERTEXTBYTES);
        fprintBstr(fp_rsp, "ss = ", ss, crypto_kem_BYTES);
        
        fprintf(fp_rsp, "\n");
        //######################## decryption #################
        total_cycles = 0;
        start_cycles = rdtsc();
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            fprintf(stderr, "crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        end_cycles = rdtsc();
        dec_avg += (end_cycles - start_cycles);
        
        
    

        //####################################################
        
        if ( memcmp(ss, ss1, crypto_kem_BYTES) ) {
            fprintf(stderr, "crypto_kem_dec returned bad 'ss' value\n");
            return KAT_CRYPTO_FAILURE;
        }
    }
    
    
    //fprintf(output_file,"******************************************************************\n");
        fprintf(output_file,"encryption\n");
        fprintf(output_file, "Average CPU cycles per iteration: %lu\n", (unsigned long)(enc_avg / KATNUM));
        //fprintf(output_file,"******************************************************************\n\n");
    //fprintf(output_file,"******************************************************************\n");
        fprintf(output_file,"decryption\n");
        fprintf(output_file, "Average CPU cycles per iteration: %lu\n", (unsigned long)(dec_avg / KATNUM));
        //fprintf(output_file,"******************************************************************\n\n");
    fclose(output_file);
    return KAT_SUCCESS;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}
