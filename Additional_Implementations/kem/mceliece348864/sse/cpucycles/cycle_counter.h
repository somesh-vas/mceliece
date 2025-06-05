// cycle_counter.h
#ifndef CYCLE_COUNTER_H
#define CYCLE_COUNTER_H

#include <stdint.h>

extern uint64_t total_cycles;

void update_cycles(uint64_t cycles);

#endif

