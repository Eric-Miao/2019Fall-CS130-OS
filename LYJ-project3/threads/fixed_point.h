#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

/*type of fixed point*/
typedef int fixed_t;
/*The number of shifts to make the 32 bit*/
#define FP_SHIFT_AMOUNT 16
/*int to fixed_t*/
#define fp_transfer(A) ((fixed_t)(A << FP_SHIFT_AMOUNT))
/*Get integer part of a fixed_t value*/
#define fp_to_int(A) (A >> FP_SHIFT_AMOUNT)
/*Add two fixed_t value*/
#define fp_add(A,B) (A + B)
/*Sub operation with two fixed_t value*/
#define fp_sub(A,B) (A - B)
/*Multiply two fixed_t value*/
#define fp_mul(A,B) ((fixed_t)(((int64_t) A) * B >> FP_SHIFT_AMOUNT))
/*Divide two fixed_t value*/
#define fp_div(A,B) ((fixed_t)((((int64_t) A) << FP_SHIFT_AMOUNT) / B))
/*Add a fixed_t value A with an int value B*/
#define fp_mix_add(A,B) (A + (B << FP_SHIFT_AMOUNT))
/*Sub operation with an int value B and a fixed_t value A*/
#define fp_mix_sub(A,B) (A - (B << FP_SHIFT_AMOUNT))
/*Mult a fixed_t value A by an int value B*/
#define fp_mix_mul(A,B) (A * B)
/*Divide a fixed_t value A by an int value B*/
#define fp_mix_div(A,B) (A / B)
/*Get rounded integer of a fixed_t value*/
#define fp_round(A) (A >= 0 ? ((A + (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT) \
        :((A - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))
#endif/* threads/fixed_point.h */