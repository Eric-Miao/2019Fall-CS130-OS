#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

#define FIXED_Q 14
#define FIXED_F (1 << (FIXED_Q))

#define TO_FIXED(n) ((n) * FIXED_F)
#define TO_INT_ZERO(x) ((x) / FIXED_F)
#define TO_INT_NEAR(x) ((x) >= 0 ? (((x) + FIXED_F / 2) / FIXED_F) \
                        : (((x) - FIXED_F / 2) / FIXED_F))

#define ADD(x, y) ((x) + (y))
#define SUB(x, y) ((x) - (y))
#define MUL(x, y) ((int64_t) (x) * (y) / FIXED_F)
#define DIV(x, y) ((int64_t) (x) * FIXED_F / (y))

#define ADD_INT(x, n) ((x) + (n) * FIXED_F)
#define SUB_INT(x, n) ((x) - (n) * FIXED_F)
#define MUL_INT(x, n) ((x) * (n))
#define DIV_INT(x, n) ((x) / (n))

#endif  /* threads/fixed-point.h */
