#ifndef XTYPES_H
#define XTYPES_H

#include <stdint.h>
#include <stddef.h> // for size_t, ssize_t



#define MAKEUSED(x) ((void)(x))
#define MIN(a, b) (((a)<(b))?(a):(b))
#define MAX(a, b) (((a)>(b))?(a):(b))

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef u8 byte;
typedef i32 bool32;

typedef float  f32;
typedef double f64;

typedef int unsigned uint;



#endif /* XTYPES_H */
