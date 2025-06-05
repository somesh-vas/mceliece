/*
  This file is for the Berlekamp-Massey algorithm
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

#include "params.h"
#include "gf.h"
#include "bm.h"
#include "stdio.h"
#include "nist/cpucycles.h"

#define min(a, b) ((a < b) ? a : b)

/* the Berlekamp-Massey algorithm */
/* input: s, sequence of field elements */
/* output: out, minimal polynomial of s */
void bm(gf *out, gf *s)
{
	int i;
	//#############################################
	uint64_t start_cycles, end_cycles, total_cycles = 0;
    FILE *output_file;
    output_file = fopen("cpucycles/BM_Cycles.txt", "a");
    start_cycles = rdtsc();
	//#############################################
	uint16_t N = 0;
	uint16_t L = 0;
	uint16_t mle;
	uint16_t mne;

	gf T[ SYS_T+1  ];
	gf C[ SYS_T+1 ];
	gf B[ SYS_T+1 ];

	gf b = 1, d, f;

	//

	for (i = 0; i < SYS_T+1; i++)
		C[i] = B[i] = 0;

	B[1] = C[0] = 1;

	//

	for (N = 0; N < 2 * SYS_T; N++)
	{
		d = 0;

		for (i = 0; i <= min(N, SYS_T); i++)
			d ^= gf_mul(C[i], s[ N-i]);
	
		mne = d; mne -= 1;   mne >>= 15; mne -= 1;
		mle = N; mle -= 2*L; mle >>= 15; mle -= 1;
		mle &= mne;

		for (i = 0; i <= SYS_T; i++)			
			T[i] = C[i];

		f = gf_frac(b, d);

		for (i = 0; i <= SYS_T; i++)			
			C[i] ^= gf_mul(f, B[i]) & mne;

		L = (L & ~mle) | ((N+1-L) & mle);

		for (i = 0; i <= SYS_T; i++)			
			B[i] = (B[i] & ~mle) | (T[i] & mle);

		b = (b & ~mle) | (d & mle);

		for (i = SYS_T; i >= 1; i--) B[i] = B[i-1];
		B[0] = 0;
	}

	for (i = 0; i <= SYS_T; i++)
		out[i] = C[ SYS_T-i ];
	end_cycles = rdtsc();
    total_cycles = (end_cycles - start_cycles);
    printf("TOTAL CYCLE: %ld\n" ,total_cycles);
    fprintf(output_file, "******************************************************************\n");
    fprintf(output_file, "The Berlekamp-Massey algorithm is a method for finding the shortest linear feedback shift register (LFSR) that can produce a given binary sequence. This algorithm is often used in coding theory and cryptography for error detection and correction codes.\n");
    fprintf(output_file, "\nAverage CPU cycles of syndrome: %lu\n", (unsigned long) total_cycles);
    fprintf(output_file, "******************************************************************\n\n");
    fclose(output_file);
}

