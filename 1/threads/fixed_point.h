#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H 

typedef int fixed_point;

/* Define shift amount. */
#define SHIFT 16

/* Value convert type. */
#define FIXED(x) ((fixed_point)((x) << SHIFT ))

/* Round to nearest. */
#define ROUND(x) ((x) >= 0 ? (((x) + (1 << (SHIFT - 1))) >> SHIFT) \
                            : (((x) - (1 << (SHIFT - 1))) >> SHIFT))

/* Round to zero. */
#define INT_CONVERT(x) ((x) >> SHIFT)

/* Add two fixed points*/
#define ADD(x, y) ((x) + (y))

/* Add fixed (A) and int (B). */
#define ADD_INT(x, y) ((x) + FIXED(y))

/* Subtract a fixed (B) from another (A). */
#define SUB(x, y) (x - y)

/* Subtract a int (B) from fixed (A). */
#define SUB_INT(x, y) ((x) - FIXED(y))

/* Multiply a fixed (A) and another (B). */
#define MUL(x, y) ((fixed_point)(((int64_t) (x)) * (y) >> SHIFT))

/* Miltiply a fixed (A) and a int (B). */
#define MUL_INT(x, y) ((x) * (y))

/* Divide a fixed (A) by anohter (B). */
#define DIV(x, y) ((fixed_point)((((int64_t) (x)) << SHIFT) / (y)))

/* Divide a fixed (A) by an int (B). */
#define DIV_INT(x, y) ((x) / (y))

#endif /* thread/fixed_point.h */

