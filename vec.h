#ifndef MY_VEC_H
#define MY_VEC_H

#include <stdint.h>
#include <stdio.h>

typedef struct my_ngtcp2_vec {
	uint8_t *base;
	size_t len;
} my_ngtcp2_vec;

#endif /* MY_VEC_H */
