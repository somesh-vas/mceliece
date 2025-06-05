// cycle_counter.c
#include <stdio.h>
#include "cpucycles/cpucycles.h"

uint64_t total_cycles = 0;
// cycle_counter.c
#include "cycle_counter.h"

void update_cycles(uint64_t cycles) {
    total_cycles += cycles;
}

