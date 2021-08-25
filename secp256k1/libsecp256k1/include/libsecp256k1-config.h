#pragma once

//optimizations that any compiler we target have

#if defined (_MSC_VER)
#else
  #define HAVE_BUILTIN_CLZLL 1
  #define HAVE_BUILTIN_EXPECT 1
#endif

#if defined (_MSC_VER)
#else
    #define HAVE___INT128 1
#endif

//use GMP for bignum
#define HAVE_LIBGMP 1
#define USE_NUM_GMP 1
#define USE_FIELD_INV_NUM 1
#define USE_SCALAR_INV_NUM 1

//use impls best for 64-bit

#if defined (_MSC_VER)
  #define USE_FIELD_10X26 1
  #define USE_SCALAR_8X32 1
#else
  #define USE_FIELD_5X52 1
  #define USE_SCALAR_4X64 1
#endif

//enable asm
#ifdef __x86_64__
  #define USE_ASM_X86_64 1
#endif