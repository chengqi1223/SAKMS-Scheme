/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include"windows_projective.h"

#ifndef uECC_PLATFORM
#if __AVR__
#define uECC_PLATFORM uECC_avr
#elif defined(__thumb2__) || defined(_M_ARMT) /* I think MSVC only supports Thumb-2 targets */
#define uECC_PLATFORM uECC_arm_thumb2
#elif defined(__thumb__)
#define uECC_PLATFORM uECC_arm_thumb
#elif defined(__arm__) || defined(_M_ARM)
#define uECC_PLATFORM uECC_arm
#elif defined(__i386__) || defined(_M_IX86) || defined(_X86_) || defined(__I86__)
#define uECC_PLATFORM uECC_x86
#elif defined(__amd64__) || defined(_M_X64)
#define uECC_PLATFORM uECC_x86_64
#else
#define uECC_PLATFORM uECC_arch_other
#endif
#endif

#ifndef uECC_WORD_SIZE
#if uECC_PLATFORM == uECC_avr
#define uECC_WORD_SIZE 1
#elif (uECC_PLATFORM == uECC_x86_64)
#define uECC_WORD_SIZE 4
#else
#define uECC_WORD_SIZE 4
#endif
#endif

#if (uECC_CURVE == uECC_secp160r1 || uECC_CURVE == uECC_secp224r1) && (uECC_WORD_SIZE == 8)
#undef uECC_WORD_SIZE
#define uECC_WORD_SIZE 4
#if (uECC_PLATFORM == uECC_x86_64)
#undef uECC_PLATFORM
#define uECC_PLATFORM uECC_x86
#endif
#endif

#if (uECC_WORD_SIZE != 1) && (uECC_WORD_SIZE != 4) && (uECC_WORD_SIZE != 8)
#error "Unsupported value for uECC_WORD_SIZE"
#endif

#if (uECC_ASM && (uECC_PLATFORM == uECC_avr) && (uECC_WORD_SIZE != 1))
#pragma message ("uECC_WORD_SIZE must be 1 when using AVR asm")
#undef uECC_WORD_SIZE
#define uECC_WORD_SIZE 1
#endif

#if (uECC_ASM && \
     (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb) && \
     (uECC_WORD_SIZE != 4))
#pragma message ("uECC_WORD_SIZE must be 4 when using ARM asm")
#undef uECC_WORD_SIZE
#define uECC_WORD_SIZE 4
#endif

#if __STDC_VERSION__ >= 199901L
#define RESTRICT restrict
#else
#define RESTRICT
#endif

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
#define SUPPORTS_INT128 1
#else
#define SUPPORTS_INT128 0
#endif

#define MAX_TRIES 64

#if (uECC_WORD_SIZE == 1)

typedef uint8_t uECC_word_t;
typedef uint16_t uECC_dword_t;
typedef uint8_t wordcount_t;
typedef int8_t swordcount_t;
typedef int16_t bitcount_t;
typedef int8_t cmpresult_t;

#define HIGH_BIT_SET 0x80
#define uECC_WORD_BITS 8
#define uECC_WORD_BITS_SHIFT 3
#define uECC_WORD_BITS_MASK 0x07

#define uECC_WORDS_1 20
#define uECC_WORDS_2 24
#define uECC_WORDS_3 32
#define uECC_WORDS_4 32
#define uECC_WORDS_5 28

#define uECC_N_WORDS_1 21
#define uECC_N_WORDS_2 24
#define uECC_N_WORDS_3 32
#define uECC_N_WORDS_4 32
#define uECC_N_WORDS_5 28

#define Curve_P_1 {0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_2 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_3 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_4 {0x2F, 0xFC, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_P_5 {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF}


#define Curve_A_1 {0xFC, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_A_2 {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}



#define Curve_B_1 {0x45, 0xFA, 0x65, 0xC5, 0xAD, 0xD4, 0xD4, 0x81, \
                   0x9F, 0xF8, 0xAC, 0x65, 0x8B, 0x7A, 0xBD, 0x54, \
                   0xFC, 0xBE, 0x97, 0x1C}
#define Curve_B_2 {0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE, \
                   0x49, 0x30, 0x24, 0x72, 0xAB, 0xE9, 0xA7, 0x0F, \
                   0xE7, 0x80, 0x9C, 0xE5, 0x19, 0x05, 0x21, 0x64}
#define Curve_B_3 {0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, \
                   0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65, \
                   0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3, \
                   0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A}
#define Curve_B_4 {0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
#define Curve_B_5 {0xB4, 0xFF, 0x55, 0x23, 0x43, 0x39, 0x0B, 0x27, \
                   0xBA, 0xD8, 0xBF, 0xD7, 0xB7, 0xB0, 0x44, 0x50, \
                   0x56, 0x32, 0x41, 0xF5, 0xAB, 0xB3, 0x04, 0x0C, \
                   0x85, 0x0A, 0x05, 0xB4}

#define Curve_G_1 { \
    {0x82, 0xFC, 0xCB, 0x13, 0xB9, 0x8B, 0xC3, 0x68, \
        0x89, 0x69, 0x64, 0x46, 0x28, 0x73, 0xF5, 0x8E, \
        0x68, 0xB5, 0x96, 0x4A}, \
    {0x32, 0xFB, 0xC5, 0x7A, 0x37, 0x51, 0x23, 0x04, \
        0x12, 0xC9, 0xDC, 0x59, 0x7D, 0x94, 0x68, 0x31, \
        0x55, 0x28, 0xA6, 0x23}}

#define Curve_G_2 { \
    {0x12, 0x10, 0xFF, 0x82, 0xFD, 0x0A, 0xFF, 0xF4, \
        0x00, 0x88, 0xA1, 0x43, 0xEB, 0x20, 0xBF, 0x7C, \
        0xF6, 0x90, 0x30, 0xB0, 0x0E, 0xA8, 0x8D, 0x18}, \
    {0x11, 0x48, 0x79, 0x1E, 0xA1, 0x77, 0xF9, 0x73, \
        0xD5, 0xCD, 0x24, 0x6B, 0xED, 0x11, 0x10, 0x63, \
        0x78, 0xDA, 0xC8, 0xFF, 0x95, 0x2B, 0x19, 0x07}}

#define Curve_G_3 { \
    {0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4, \
        0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77, \
        0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8, \
        0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B}, \
    {0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB, \
        0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B, \
        0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E, \
        0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F}}

#define Curve_G_4 { \
    {0x98, 0x17, 0xF8, 0x16, 0x5B, 0x81, 0xF2, 0x59, \
        0xD9, 0x28, 0xCE, 0x2D, 0xDB, 0xFC, 0x9B, 0x02, \
        0x07, 0x0B, 0x87, 0xCE, 0x95, 0x62, 0xA0, 0x55, \
        0xAC, 0xBB, 0xDC, 0xF9, 0x7E, 0x66, 0xBE, 0x79}, \
    {0xB8, 0xD4, 0x10, 0xFB, 0x8F, 0xD0, 0x47, 0x9C, \
        0x19, 0x54, 0x85, 0xA6, 0x48, 0xB4, 0x17, 0xFD, \
        0xA8, 0x08, 0x11, 0x0E, 0xFC, 0xFB, 0xA4, 0x5D, \
        0x65, 0xC4, 0xA3, 0x26, 0x77, 0xDA, 0x3A, 0x48}}

#define Curve_G_5 { \
    {0x21, 0x1D, 0x5C, 0x11, 0xD6, 0x80, 0x32, 0x34, \
        0x22, 0x11, 0xC2, 0x56, 0xD3, 0xC1, 0x03, 0x4A, \
        0xB9, 0x90, 0x13, 0x32, 0x7F, 0xBF, 0xB4, 0x6B, \
        0xBD, 0x0C, 0x0E, 0xB7}, \
    {0x34, 0x7E, 0x00, 0x85, 0x99, 0x81, 0xD5, 0x44, \
        0x64, 0x47, 0x07, 0x5A, 0xA0, 0x75, 0x43, 0xCD, \
        0xE6, 0xDF, 0x22, 0x4C, 0xFB, 0x23, 0xF7, 0xB5, \
        0x88, 0x63, 0x37, 0xBD}}

#define Curve_N_1 {0x57, 0x22, 0x75, 0xCA, 0xD3, 0xAE, 0x27, 0xF9, \
                   0xC8, 0xF4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x01}
#define Curve_N_2 {0x31, 0x28, 0xD2, 0xB4, 0xB1, 0xC9, 0x6B, 0x14, \
                   0x36, 0xF8, 0xDE, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_N_3 {0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3, \
                   0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_N_4 {0x41, 0x41, 0x36, 0xD0, 0x8C, 0x5E, 0xD2, 0xBF, \
                   0x3B, 0xA0, 0x48, 0xAF, 0xE6, 0xDC, 0xAE, 0xBA, \
                   0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define Curve_N_5 {0x3D, 0x2A, 0x5C, 0x5C, 0x45, 0x29, 0xDD, 0x13, \
                   0x3E, 0xF0, 0xB8, 0xE0, 0xA2, 0x16, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                   0xFF, 0xFF, 0xFF, 0xFF}

#elif (uECC_WORD_SIZE == 4)

typedef uint32_t uECC_word_t;
typedef uint64_t uECC_dword_t;
typedef unsigned wordcount_t;
typedef int swordcount_t;
typedef int bitcount_t;
typedef int cmpresult_t;

#define HIGH_BIT_SET 0x80000000
#define uECC_WORD_BITS 32
#define uECC_WORD_BITS_SHIFT 5
#define uECC_WORD_BITS_MASK 0x01F
#define uECC_WORD_BITS_SHIFT_1 3
#define uECC_WORD_BITS_MASK_1 0x07

#define uECC_WORDS_1 5
#define uECC_WORDS_2 6
#define uECC_WORDS_3 8
#define uECC_WORDS_4 8
#define uECC_WORDS_5 7

#define uECC_N_WORDS_1 6
#define uECC_N_WORDS_2 6
#define uECC_N_WORDS_3 8
#define uECC_N_WORDS_4 8
#define uECC_N_WORDS_5 7

#define Curve_P_1 {0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_P_2 {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_P_3 {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, \
                   0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF}
#define Curve_P_4 {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, \
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_P_5 {0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, \
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}

#define Curve_A_1 {0x7FFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_A_2 {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_A_4 {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}


#define Curve_B_1 {0xC565FA45, 0x81D4D4AD, 0x65ACF89F, 0x54BD7A8B, 0x1C97BEFC}
#define Curve_B_2 {0xC146B9B1, 0xFEB8DEEC, 0x72243049, 0x0FA7E9AB, 0xE59C80E7, 0x64210519}
#define Curve_B_3 {0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, \
                   0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8}
#define Curve_B_4 {0x00000007, 0x00000000, 0x00000000, 0x00000000, \
                   0x00000000, 0x00000000, 0x00000000, 0x00000000}
#define Curve_B_5 {0x2355FFB4, 0x270B3943, 0xD7BFD8BA, 0x5044B0B7, \
                   0xF5413256, 0x0C04B3AB, 0xB4050A85}

#define Curve_G_1 { \
    {0x13CBFC82, 0x68C38BB9, 0x46646989, 0x8EF57328, 0x4A96B568}, \
    {0x7AC5FB32, 0x04235137, 0x59DCC912, 0x3168947D, 0x23A62855}}

#define Curve_G_2 { \
    {0x82FF1012, 0xF4FF0AFD, 0x43A18800, 0x7CBF20EB, 0xB03090F6, 0x188DA80E}, \
    {0x1E794811, 0x73F977A1, 0x6B24CDD5, 0x631011ED, 0xFFC8DA78, 0x07192B95}}

#define Curve_G_3 { \
    {0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,  \
     0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2}, \
    {0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,  \
     0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2}}

#define Curve_G_4 { \
    {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,  \
     0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}, \
    {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,  \
     0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}}

#define Curve_G_5 { \
    {0x115C1D21, 0x343280D6, 0x56C21122, 0x4A03C1D3, \
     0x321390B9, 0x6BB4BF7F, 0xB70E0CBD}, \
    {0x85007E34, 0x44D58199, 0x5A074764, 0xCD4375A0, \
     0x4C22DFE6, 0xB5F723FB, 0xBD376388}}

#define Curve_N_1 {0xCA752257, 0xF927AED3, 0x0001F4C8, 0x00000000, 0x00000000, 0x00000001}
#define Curve_N_2 {0xB4D22831, 0x146BC9B1, 0x99DEF836, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_N_3 {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, \
                   0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF}
#define Curve_N_4 {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, \
                   0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_N_5 {0x5C5C2A3D, 0x13DD2945, 0xE0B8F03E, 0xFFFF16A2, \
                   0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}

#elif (uECC_WORD_SIZE == 8)

typedef uint64_t uECC_word_t;
#if SUPPORTS_INT128
typedef unsigned __int128 uECC_dword_t;
#endif
typedef unsigned wordcount_t;
typedef int swordcount_t;
typedef int bitcount_t;
typedef int cmpresult_t;

#define HIGH_BIT_SET 0x8000000000000000ull
#define uECC_WORD_BITS 64
#define uECC_WORD_BITS_SHIFT 6
#define uECC_WORD_BITS_MASK 0x03F

#define uECC_WORDS_1 3
#define uECC_WORDS_2 3
#define uECC_WORDS_3 4
#define uECC_WORDS_4 4
#define uECC_WORDS_5 4

#define uECC_N_WORDS_1 3
#define uECC_N_WORDS_2 3
#define uECC_N_WORDS_3 4
#define uECC_N_WORDS_4 4
#define uECC_N_WORDS_5 4

#define Curve_P_1 {0xFFFFFFFF7FFFFFFFull, 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull}
#define Curve_P_2 {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_P_3 {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, \
                   0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#define Curve_P_4 {0xFFFFFFFEFFFFFC2Full, 0xFFFFFFFFFFFFFFFFull, \
                   0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_P_5 {0x0000000000000001ull, 0xFFFFFFFF00000000ull, \
                   0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull}

#define Curve_A_1 {0xFFFFFFFF7FFFFFCFull, 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull}
#define Curve_A_2 {0xFFFFFFFFFFFFFFCFull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}

#define Curve_B_1 {0x81D4D4ADC565FA45ull, 0x54BD7A8B65ACF89Full, 0x000000001C97BEFCull}
#define Curve_B_2 {0xFEB8DEECC146B9B1ull, 0x0FA7E9AB72243049ull, 0x64210519E59C80E7ull}
#define Curve_B_3 {0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, \
                   0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}
#define Curve_B_4 {0x0000000000000007ull, 0x0000000000000000ull, \
                   0x0000000000000000ull, 0x0000000000000000ull}
#define Curve_B_5 {0x270B39432355FFB4ull, 0x5044B0B7D7BFD8BAull, \
                   0x0C04B3ABF5413256ull, 0x00000000B4050A85ull}

#define Curve_G_1 { \
    {0x68C38BB913CBFC82ull, 0x8EF5732846646989ull, 0x000000004A96B568ull}, \
    {0x042351377AC5FB32ull, 0x3168947D59DCC912ull, 0x0000000023A62855ull}}

#define Curve_G_2 { \
    {0xF4FF0AFD82FF1012ull, 0x7CBF20EB43A18800ull, 0x188DA80EB03090F6ull}, \
    {0x73F977A11E794811ull, 0x631011ED6B24CDD5ull, 0x07192B95FFC8DA78ull}}

#define Curve_G_3 { \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull}}

#define Curve_G_4 { \
    {0x59F2815B16F81798ull, 0x029BFCDB2DCE28D9ull, 0x55A06295CE870B07ull, 0x79BE667EF9DCBBACull}, \
    {0x9C47D08FFB10D4B8ull, 0xFD17B448A6855419ull, 0x5DA4FBFC0E1108A8ull, 0x483ADA7726A3C465ull}}

#define Curve_G_5 { \
    {0x343280D6115C1D21ull, 0x4A03C1D356C21122ull, 0x6BB4BF7F321390B9ull, 0x00000000B70E0CBDull}, \
    {0x44D5819985007E34ull, 0xCD4375A05A074764ull, 0xB5F723FB4C22DFE6ull, 0x00000000BD376388ull}}

#define Curve_N_1 {0xF927AED3CA752257ull, 0x000000000001F4C8ull, 0x0000000100000000ull}
#define Curve_N_2 {0x146BC9B1B4D22831ull, 0xFFFFFFFF99DEF836ull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_N_3 {0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, \
                   0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull}
#define Curve_N_4 {0xBFD25E8CD0364141ull, 0xBAAEDCE6AF48A03Bull, \
                   0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_N_5 {0x13DD29455C5C2A3Dull, 0xFFFF16A2E0B8F03Eull, \
                   0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull}

#endif /* (uECC_WORD_SIZE == 8) */

#define uECC_WORDS uECC_CONCAT(uECC_WORDS_, uECC_CURVE)
#define uECC_N_WORDS uECC_CONCAT(uECC_N_WORDS_, uECC_CURVE)

typedef struct EccPoint {
    uECC_word_t x[uECC_WORDS];
    uECC_word_t y[uECC_WORDS];
} EccPoint;

static const uECC_word_t curve_p[uECC_WORDS] = uECC_CONCAT(Curve_P_, uECC_CURVE);
static const uECC_word_t curve_a[uECC_WORDS] = uECC_CONCAT(Curve_A_, uECC_CURVE);
static const uECC_word_t curve_b[uECC_WORDS] = uECC_CONCAT(Curve_B_, uECC_CURVE);
static const EccPoint curve_G = uECC_CONCAT(Curve_G_, uECC_CURVE);
static const uECC_word_t curve_n[uECC_N_WORDS] = uECC_CONCAT(Curve_N_, uECC_CURVE);

static void vli_clear(uECC_word_t* vli);
static uECC_word_t vli_isZero(const uECC_word_t* vli);
static uECC_word_t vli_testBit(const uECC_word_t* vli, bitcount_t bit);
static bitcount_t vli_numBits(const uECC_word_t* vli, wordcount_t max_words);
static void vli_set(uECC_word_t* dest, const uECC_word_t* src);
static cmpresult_t vli_cmp(const uECC_word_t* left, const uECC_word_t* right);
static cmpresult_t vli_equal(const uECC_word_t* left, const uECC_word_t* right);
static void vli_rshift1(uECC_word_t* vli);
static uECC_word_t vli_add(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right);
static uECC_word_t vli_sub(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right);
static void vli_mult(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right);
static void vli_modAdd(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right,
    const uECC_word_t* mod);
static void vli_modSub(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right,
    const uECC_word_t* mod);
static void vli_mmod_fast(uECC_word_t* RESTRICT result, uECC_word_t* RESTRICT product);
static void vli_modMult_fast(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right);
static void vli_modInv(uECC_word_t* result, const uECC_word_t* input, const uECC_word_t* mod);
#if uECC_SQUARE_FUNC
static void vli_square(uECC_word_t* result, const uECC_word_t* left);
static void vli_modSquare_fast(uECC_word_t* result, const uECC_word_t* left);
#endif

#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int default_RNG(uint8_t* dest, unsigned size) {
    HCRYPTPROV prov;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }

    CryptGenRandom(prov, size, (BYTE*)dest);
    CryptReleaseContext(prov, 0);
    return 1;
}

#elif defined(unix) || defined(__linux__) || defined(__unix__) || defined(__unix) || \
    (defined(__APPLE__) && defined(__MACH__)) || defined(uECC_POSIX)

/* Some POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int default_RNG(uint8_t* dest, unsigned size) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            return 0;
        }
    }

    char* ptr = (char*)dest;
    size_t left = size;
    while (left > 0) {
        ssize_t bytes_read = read(fd, ptr, left);
        if (bytes_read <= 0) { // read failed
            close(fd);
            return 0;
        }
        left -= bytes_read;
        ptr += bytes_read;
    }

    close(fd);
    return 1;
}

#else /* Some other platform */

static int default_RNG(uint8_t* dest, unsigned size) {
    return 0;
}

#endif


#ifdef __GNUC__ /* Only support GCC inline asm for now */
#if (uECC_ASM && (uECC_PLATFORM == uECC_avr))
#include "asm_avr.inc"
#endif

#if (uECC_ASM && (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb || \
                      uECC_PLATFORM == uECC_arm_thumb2))
#include "asm_arm.inc"
#endif
#endif

#if !asm_clear
static void vli_clear(uECC_word_t* vli) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        vli[i] = 0;
    }
}
#endif

/* Returns 1 if vli == 0, 0 otherwise. */
#if !asm_isZero
static uECC_word_t vli_isZero(const uECC_word_t* vli) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        if (vli[i]) {
            return 0;
        }
    }
    return 1;
}
#endif

/* Returns nonzero if bit 'bit' of vli is set. */
#if !asm_testBit
static uECC_word_t vli_testBit(const uECC_word_t* vli, bitcount_t bit) {
    return (vli[bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 << (bit & uECC_WORD_BITS_MASK)));
}
#endif

/* Counts the number of words in vli. */
#if !asm_numBits
static wordcount_t vli_numDigits(const uECC_word_t* vli, wordcount_t max_words) {
    swordcount_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vli. */
static bitcount_t vli_numBits(const uECC_word_t* vli, wordcount_t max_words) {
    uECC_word_t i;
    uECC_word_t digit;

    wordcount_t num_digits = vli_numDigits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT) + i);
}
#endif /* !asm_numBits */

static uECC_word_t vli_testBit_1(const uECC_word_t* vli, bitcount_t bit) {
    uECC_word_t temp, j;
    temp = (vli[bit >> uECC_WORD_BITS_SHIFT_1] & ((uECC_word_t)15 << 4 * (bit & uECC_WORD_BITS_MASK_1)));
    j = bit & uECC_WORD_BITS_MASK_1;
    return temp >> 4 * j;
}

static bitcount_t vli_numBits_1(const uECC_word_t* vli, wordcount_t max_words) {
    uECC_word_t i;
    uECC_word_t digit;

    wordcount_t num_digits = vli_numDigits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 4;
    }

    return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT_1) + i);
}


/* Sets dest = src. */
#if !asm_set
static void vli_set(uECC_word_t* dest, const uECC_word_t* src) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        dest[i] = src[i];
    }
}
#endif

/* Returns sign of left - right. */
#if !asm_cmp
static cmpresult_t vli_cmp(const uECC_word_t* left, const uECC_word_t* right) {
    swordcount_t i;
    for (i = uECC_WORDS - 1; i >= 0; --i) {
        if (left[i] > right[i]) {
            return 1;
        }
        else if (left[i] < right[i]) {
            return -1;
        }
    }
    return 0;
}
#endif

static cmpresult_t vli_equal(const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t result = 0;
    swordcount_t i;
    for (i = uECC_WORDS - 1; i >= 0; --i) {
        result |= (left[i] ^ right[i]);
    }
    return (result == 0);
}

/* Computes vli = vli >> 1. */
#if !asm_rshift1
static void vli_rshift1(uECC_word_t* vli) {
    uECC_word_t* end = vli;
    uECC_word_t carry = 0;

    vli += uECC_WORDS;
    while (vli-- > end) {
        uECC_word_t temp = *vli;
        *vli = (temp >> 1) | carry;
        carry = temp << (uECC_WORD_BITS - 1);
    }
}
#endif

/* Computes result = left + right, returning carry. Can modify in place. */
#if !asm_add
static uECC_word_t vli_add(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t carry = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t sum = left[i] + right[i] + carry;
        if (sum != left[i]) {
            carry = (sum < left[i]);
        }
        result[i] = sum;
    }
    return carry;
}
#endif

/* Computes result = left - right, returning borrow. Can modify in place. */
#if !asm_sub
static uECC_word_t vli_sub(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}
#endif

#if (!asm_mult || (uECC_SQUARE_FUNC && !asm_square) || uECC_CURVE == uECC_secp256k1)
static void muladd(uECC_word_t a,
    uECC_word_t b,
    uECC_word_t* r0,
    uECC_word_t* r1,
    uECC_word_t* r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1) { // overflow
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}
#define muladd_exists 1
#endif

#if !asm_mult
static void vli_mult(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < uECC_WORDS; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = uECC_WORDS; k < uECC_WORDS * 2 - 1; ++k) {
        for (i = (k + 1) - uECC_WORDS; i < uECC_WORDS; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#if uECC_SQUARE_FUNC

#if !asm_square
static void mul2add(uECC_word_t a,
    uECC_word_t b,
    uECC_word_t* r0,
    uECC_word_t* r1,
    uECC_word_t* r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1)
    { // overflow
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r2 += (p1 >> 63);
    p1 = (p1 << 1) | (p0 >> 63);
    p0 <<= 1;

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    *r2 += (p >> (uECC_WORD_BITS * 2 - 1));
    p *= 2;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}

static void vli_square(uECC_word_t* result, const uECC_word_t* left) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    for (k = 0; k < uECC_WORDS * 2 - 1; ++k) {
        uECC_word_t min = (k < uECC_WORDS ? 0 : (k + 1) - uECC_WORDS);
        for (i = min; i <= k && i <= k - i; ++i) {
            if (i < k - i) {
                mul2add(left[i], left[k - i], &r0, &r1, &r2);
            }
            else {
                muladd(left[i], left[k - i], &r0, &r1, &r2);
            }
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#else /* uECC_SQUARE_FUNC */

#define vli_square(result, left, size) vli_mult((result), (left), (left), (size))

#endif /* uECC_SQUARE_FUNC */


/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
#if !asm_modAdd
static void vli_modAdd(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right,
    const uECC_word_t* mod) {
    uECC_word_t carry = vli_add(result, left, right);
    if (carry || vli_cmp(result, mod) >= 0) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        vli_sub(result, result, mod);
    }
}
#endif

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
#if !asm_modSub
static void vli_modSub(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right,
    const uECC_word_t* mod) {
    uECC_word_t l_borrow = vli_sub(result, left, right);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        vli_add(result, result, mod);
    }
}
#endif

#if !asm_modSub_fast
#define vli_modSub_fast(result, left, right) vli_modSub((result), (left), (right), curve_p)
#endif

#if !asm_mmod_fast

#if (uECC_CURVE == uECC_secp160r1 || uECC_CURVE == uECC_secp256k1)
/* omega_mult() is defined farther below for the different curves / word sizes */
static void omega_mult(uECC_word_t* RESTRICT result, const uECC_word_t* RESTRICT right);

/* Computes result = product % curve_p
    see http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf page 354
    Note that this only works if log2(omega) < log2(p) / 2 */
static void vli_mmod_fast(uECC_word_t* RESTRICT result, uECC_word_t* RESTRICT product) {
    uECC_word_t tmp[2 * uECC_WORDS];
    uECC_word_t carry;

    vli_clear(tmp);
    vli_clear(tmp + uECC_WORDS);

    omega_mult(tmp, product + uECC_WORDS); /* (Rq, q) = q * c */

    carry = vli_add(result, product, tmp); /* (C, r) = r + q       */
    vli_clear(product);
    omega_mult(product, tmp + uECC_WORDS); /* Rq*c */
    carry += vli_add(result, result, product); /* (C1, r) = r + Rq*c */

    while (carry > 0) {
        --carry;
        vli_sub(result, result, curve_p);
    }
    if (vli_cmp(result, curve_p) > 0) {
        vli_sub(result, result, curve_p);
    }
}

#endif

#if uECC_CURVE == uECC_secp160r1

#if uECC_WORD_SIZE == 1
static void omega_mult(uint8_t* RESTRICT result, const uint8_t* RESTRICT right) {
    uint8_t carry;
    uint8_t i;

    /* Multiply by (2^31 + 1). */
    vli_set(result + 4, right); /* 2^32 */
    vli_rshift1(result + 4); /* 2^31 */
    result[3] = right[0] << 7; /* get last bit from shift */

    carry = vli_add(result, result, right); /* 2^31 + 1 */
    for (i = uECC_WORDS; carry; ++i) {
        uint16_t sum = (uint16_t)result[i] + carry;
        result[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}
#elif uECC_WORD_SIZE == 4
static void omega_mult(uint32_t* RESTRICT result, const uint32_t* RESTRICT right) {
    uint32_t carry;
    unsigned i;

    /* Multiply by (2^31 + 1). */
    vli_set(result + 1, right); /* 2^32 */
    vli_rshift1(result + 1); /* 2^31 */
    result[0] = right[0] << 31; /* get last bit from shift */

    carry = vli_add(result, result, right); /* 2^31 + 1 */
    for (i = uECC_WORDS; carry; ++i) {
        uint64_t sum = (uint64_t)result[i] + carry;
        result[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp192r1

/* Computes result = product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
#if uECC_WORD_SIZE == 1
static void vli_mmod_fast(uint8_t* RESTRICT result, uint8_t* RESTRICT product) {
    uint8_t tmp[uECC_WORDS];
    uint8_t carry;

    vli_set(result, product);

    vli_set(tmp, &product[24]);
    carry = vli_add(result, result, tmp);

    tmp[0] = tmp[1] = tmp[2] = tmp[3] = tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = product[24]; tmp[9] = product[25]; tmp[10] = product[26]; tmp[11] = product[27];
    tmp[12] = product[28]; tmp[13] = product[29]; tmp[14] = product[30]; tmp[15] = product[31];
    tmp[16] = product[32]; tmp[17] = product[33]; tmp[18] = product[34]; tmp[19] = product[35];
    tmp[20] = product[36]; tmp[21] = product[37]; tmp[22] = product[38]; tmp[23] = product[39];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[8] = product[40];
    tmp[1] = tmp[9] = product[41];
    tmp[2] = tmp[10] = product[42];
    tmp[3] = tmp[11] = product[43];
    tmp[4] = tmp[12] = product[44];
    tmp[5] = tmp[13] = product[45];
    tmp[6] = tmp[14] = product[46];
    tmp[7] = tmp[15] = product[47];
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#elif uECC_WORD_SIZE == 4
static void vli_mmod_fast(uint32_t* RESTRICT result, uint32_t* RESTRICT product) {
    uint32_t tmp[uECC_WORDS];
    int carry;

    vli_set(result, product);

    vli_set(tmp, &product[6]);
    carry = vli_add(result, result, tmp);

    tmp[0] = tmp[1] = 0;
    tmp[2] = product[6];
    tmp[3] = product[7];
    tmp[4] = product[8];
    tmp[5] = product[9];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[2] = product[10];
    tmp[1] = tmp[3] = product[11];
    tmp[4] = tmp[5] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#else
static void vli_mmod_fast(uint64_t* RESTRICT result, uint64_t* RESTRICT product) {
    uint64_t tmp[uECC_WORDS];
    int carry;

    vli_set(result, product);

    vli_set(tmp, &product[3]);
    carry = vli_add(result, result, tmp);

    tmp[0] = 0;
    tmp[1] = product[3];
    tmp[2] = product[4];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[1] = product[5];
    tmp[2] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp256r1

/* Computes result = product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
#if uECC_WORD_SIZE == 1
static void vli_mmod_fast(uint8_t* RESTRICT result, uint8_t* RESTRICT product) {
    uint8_t tmp[uECC_BYTES];
    int8_t carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[44]; tmp[13] = product[45]; tmp[14] = product[46]; tmp[15] = product[47];
    tmp[16] = product[48]; tmp[17] = product[49]; tmp[18] = product[50]; tmp[19] = product[51];
    tmp[20] = product[52]; tmp[21] = product[53]; tmp[22] = product[54]; tmp[23] = product[55];
    tmp[24] = product[56]; tmp[25] = product[57]; tmp[26] = product[58]; tmp[27] = product[59];
    tmp[28] = product[60]; tmp[29] = product[61]; tmp[30] = product[62]; tmp[31] = product[63];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[12] = product[48]; tmp[13] = product[49]; tmp[14] = product[50]; tmp[15] = product[51];
    tmp[16] = product[52]; tmp[17] = product[53]; tmp[18] = product[54]; tmp[19] = product[55];
    tmp[20] = product[56]; tmp[21] = product[57]; tmp[22] = product[58]; tmp[23] = product[59];
    tmp[24] = product[60]; tmp[25] = product[61]; tmp[26] = product[62]; tmp[27] = product[63];
    tmp[28] = tmp[29] = tmp[30] = tmp[31] = 0;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[32]; tmp[1] = product[33]; tmp[2] = product[34]; tmp[3] = product[35];
    tmp[4] = product[36]; tmp[5] = product[37]; tmp[6] = product[38]; tmp[7] = product[39];
    tmp[8] = product[40]; tmp[9] = product[41]; tmp[10] = product[42]; tmp[11] = product[43];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[56]; tmp[25] = product[57]; tmp[26] = product[58]; tmp[27] = product[59];
    tmp[28] = product[60]; tmp[29] = product[61]; tmp[30] = product[62]; tmp[31] = product[63];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = product[36]; tmp[1] = product[37]; tmp[2] = product[38]; tmp[3] = product[39];
    tmp[4] = product[40]; tmp[5] = product[41]; tmp[6] = product[42]; tmp[7] = product[43];
    tmp[8] = product[44]; tmp[9] = product[45]; tmp[10] = product[46]; tmp[11] = product[47];
    tmp[12] = product[52]; tmp[13] = product[53]; tmp[14] = product[54]; tmp[15] = product[55];
    tmp[16] = product[56]; tmp[17] = product[57]; tmp[18] = product[58]; tmp[19] = product[59];
    tmp[20] = product[60]; tmp[21] = product[61]; tmp[22] = product[62]; tmp[23] = product[63];
    tmp[24] = product[52]; tmp[25] = product[53]; tmp[26] = product[54]; tmp[27] = product[55];
    tmp[28] = product[32]; tmp[29] = product[33]; tmp[30] = product[34]; tmp[31] = product[35];
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[44]; tmp[1] = product[45]; tmp[2] = product[46]; tmp[3] = product[47];
    tmp[4] = product[48]; tmp[5] = product[49]; tmp[6] = product[50]; tmp[7] = product[51];
    tmp[8] = product[52]; tmp[9] = product[53]; tmp[10] = product[54]; tmp[11] = product[55];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[32]; tmp[25] = product[33]; tmp[26] = product[34]; tmp[27] = product[35];
    tmp[28] = product[40]; tmp[29] = product[41]; tmp[30] = product[42]; tmp[31] = product[43];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[48]; tmp[1] = product[49]; tmp[2] = product[50]; tmp[3] = product[51];
    tmp[4] = product[52]; tmp[5] = product[53]; tmp[6] = product[54]; tmp[7] = product[55];
    tmp[8] = product[56]; tmp[9] = product[57]; tmp[10] = product[58]; tmp[11] = product[59];
    tmp[12] = product[60]; tmp[13] = product[61]; tmp[14] = product[62]; tmp[15] = product[63];
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[36]; tmp[25] = product[37]; tmp[26] = product[38]; tmp[27] = product[39];
    tmp[28] = product[44]; tmp[29] = product[45]; tmp[30] = product[46]; tmp[31] = product[47];
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = product[52]; tmp[1] = product[53]; tmp[2] = product[54]; tmp[3] = product[55];
    tmp[4] = product[56]; tmp[5] = product[57]; tmp[6] = product[58]; tmp[7] = product[59];
    tmp[8] = product[60]; tmp[9] = product[61]; tmp[10] = product[62]; tmp[11] = product[63];
    tmp[12] = product[32]; tmp[13] = product[33]; tmp[14] = product[34]; tmp[15] = product[35];
    tmp[16] = product[36]; tmp[17] = product[37]; tmp[18] = product[38]; tmp[19] = product[39];
    tmp[20] = product[40]; tmp[21] = product[41]; tmp[22] = product[42]; tmp[23] = product[43];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    tmp[28] = product[48]; tmp[29] = product[49]; tmp[30] = product[50]; tmp[31] = product[51];
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[56]; tmp[1] = product[57]; tmp[2] = product[58]; tmp[3] = product[59];
    tmp[4] = product[60]; tmp[5] = product[61]; tmp[6] = product[62]; tmp[7] = product[63];
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[36]; tmp[13] = product[37]; tmp[14] = product[38]; tmp[15] = product[39];
    tmp[16] = product[40]; tmp[17] = product[41]; tmp[18] = product[42]; tmp[19] = product[43];
    tmp[20] = product[44]; tmp[21] = product[45]; tmp[22] = product[46]; tmp[23] = product[47];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    tmp[28] = product[52]; tmp[29] = product[53]; tmp[30] = product[54]; tmp[31] = product[55];
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    }
    else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#elif uECC_WORD_SIZE == 4
static void vli_mmod_fast(uint32_t* RESTRICT result, uint32_t* RESTRICT product) {
    uint32_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = 0;
    tmp[3] = product[11];
    tmp[4] = product[12];
    tmp[5] = product[13];
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[3] = product[12];
    tmp[4] = product[13];
    tmp[5] = product[14];
    tmp[6] = product[15];
    tmp[7] = 0;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[8];
    tmp[1] = product[9];
    tmp[2] = product[10];
    tmp[3] = tmp[4] = tmp[5] = 0;
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = product[9];
    tmp[1] = product[10];
    tmp[2] = product[11];
    tmp[3] = product[13];
    tmp[4] = product[14];
    tmp[5] = product[15];
    tmp[6] = product[13];
    tmp[7] = product[8];
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[11];
    tmp[1] = product[12];
    tmp[2] = product[13];
    tmp[3] = tmp[4] = tmp[5] = 0;
    tmp[6] = product[8];
    tmp[7] = product[10];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[12];
    tmp[1] = product[13];
    tmp[2] = product[14];
    tmp[3] = product[15];
    tmp[4] = tmp[5] = 0;
    tmp[6] = product[9];
    tmp[7] = product[11];
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = product[13];
    tmp[1] = product[14];
    tmp[2] = product[15];
    tmp[3] = product[8];
    tmp[4] = product[9];
    tmp[5] = product[10];
    tmp[6] = 0;
    tmp[7] = product[12];
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[14];
    tmp[1] = product[15];
    tmp[2] = 0;
    tmp[3] = product[9];
    tmp[4] = product[10];
    tmp[5] = product[11];
    tmp[6] = 0;
    tmp[7] = product[13];
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    }
    else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#else
static void vli_mmod_fast(uint64_t* RESTRICT result, uint64_t* RESTRICT product) {
    uint64_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = 0;
    tmp[1] = product[5] & 0xffffffff00000000ull;
    tmp[2] = product[6];
    tmp[3] = product[7];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[1] = product[6] << 32;
    tmp[2] = (product[6] >> 32) | (product[7] << 32);
    tmp[3] = product[7] >> 32;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[4];
    tmp[1] = product[5] & 0xffffffff;
    tmp[2] = 0;
    tmp[3] = product[7];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = (product[4] >> 32) | (product[5] << 32);
    tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
    tmp[2] = product[7];
    tmp[3] = (product[6] >> 32) | (product[4] << 32);
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = (product[5] >> 32) | (product[6] << 32);
    tmp[1] = (product[6] >> 32);
    tmp[2] = 0;
    tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[6];
    tmp[1] = product[7];
    tmp[2] = 0;
    tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = (product[6] >> 32) | (product[7] << 32);
    tmp[1] = (product[7] >> 32) | (product[4] << 32);
    tmp[2] = (product[4] >> 32) | (product[5] << 32);
    tmp[3] = (product[6] << 32);
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[7];
    tmp[1] = product[4] & 0xffffffff00000000ull;
    tmp[2] = product[5];
    tmp[3] = product[6] & 0xffffffff00000000ull;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    }
    else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp256k1

#if uECC_WORD_SIZE == 1
static void omega_mult(uint8_t* RESTRICT result, const uint8_t* RESTRICT right) {
    /* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t k;

    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    muladd(0xD1, right[0], &r0, &r1, &r2);
    result[0] = r0;
    r0 = r1;
    r1 = r2;
    /* r2 is still 0 */

    for (k = 1; k < uECC_WORDS; ++k) {
        muladd(0x03, right[k - 1], &r0, &r1, &r2);
        muladd(0xD1, right[k], &r0, &r1, &r2);
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    muladd(0x03, right[uECC_WORDS - 1], &r0, &r1, &r2);
    result[uECC_WORDS] = r0;
    result[uECC_WORDS + 1] = r1;

    result[4 + uECC_WORDS] = vli_add(result + 4, result + 4, right); /* add the 2^32 multiple */
}
#elif uECC_WORD_SIZE == 4
static void omega_mult(uint32_t* RESTRICT result, const uint32_t* RESTRICT right) {
    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uint32_t carry = 0;
    wordcount_t k;

    for (k = 0; k < uECC_WORDS; ++k) {
        uint64_t p = (uint64_t)0x3D1 * right[k] + carry;
        result[k] = (p & 0xffffffff);
        carry = p >> 32;
    }
    result[uECC_WORDS] = carry;

    result[1 + uECC_WORDS] = vli_add(result + 1, result + 1, right); /* add the 2^32 multiple */
}
#else
static void omega_mult(uint64_t* RESTRICT result, const uint64_t* RESTRICT right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t k;

    /* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    for (k = 0; k < uECC_WORDS; ++k) {
        muladd(0x1000003D1ull, right[k], &r0, &r1, &r2);
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_WORDS] = r0;
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp224r1

/* Computes result = product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
#if uECC_WORD_SIZE == 1
   // TODO it may be faster to use the omega_mult method when fully asm optimized.
void vli_mmod_fast(uint8_t* RESTRICT result, uint8_t* RESTRICT product) {
    uint8_t tmp[uECC_WORDS];
    int8_t carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[28]; tmp[13] = product[29]; tmp[14] = product[30]; tmp[15] = product[31];
    tmp[16] = product[32]; tmp[17] = product[33]; tmp[18] = product[34]; tmp[19] = product[35];
    tmp[20] = product[36]; tmp[21] = product[37]; tmp[22] = product[38]; tmp[23] = product[39];
    tmp[24] = product[40]; tmp[25] = product[41]; tmp[26] = product[42]; tmp[27] = product[43];
    carry = vli_add(result, result, tmp);

    /* s2 */
    tmp[12] = product[44]; tmp[13] = product[45]; tmp[14] = product[46]; tmp[15] = product[47];
    tmp[16] = product[48]; tmp[17] = product[49]; tmp[18] = product[50]; tmp[19] = product[51];
    tmp[20] = product[52]; tmp[21] = product[53]; tmp[22] = product[54]; tmp[23] = product[55];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[28]; tmp[1] = product[29]; tmp[2] = product[30]; tmp[3] = product[31];
    tmp[4] = product[32]; tmp[5] = product[33]; tmp[6] = product[34]; tmp[7] = product[35];
    tmp[8] = product[36]; tmp[9] = product[37]; tmp[10] = product[38]; tmp[11] = product[39];
    tmp[12] = product[40]; tmp[13] = product[41]; tmp[14] = product[42]; tmp[15] = product[43];
    tmp[16] = product[44]; tmp[17] = product[45]; tmp[18] = product[46]; tmp[19] = product[47];
    tmp[20] = product[48]; tmp[21] = product[49]; tmp[22] = product[50]; tmp[23] = product[51];
    tmp[24] = product[52]; tmp[25] = product[53]; tmp[26] = product[54]; tmp[27] = product[55];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[44]; tmp[1] = product[45]; tmp[2] = product[46]; tmp[3] = product[47];
    tmp[4] = product[48]; tmp[5] = product[49]; tmp[6] = product[50]; tmp[7] = product[51];
    tmp[8] = product[52]; tmp[9] = product[53]; tmp[10] = product[54]; tmp[11] = product[55];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    }
    else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#elif uECC_WORD_SIZE == 4
void vli_mmod_fast(uint32_t* RESTRICT result, uint32_t* RESTRICT product)
{
    uint32_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = 0;
    tmp[3] = product[7];
    tmp[4] = product[8];
    tmp[5] = product[9];
    tmp[6] = product[10];
    carry = vli_add(result, result, tmp);

    /* s2 */
    tmp[3] = product[11];
    tmp[4] = product[12];
    tmp[5] = product[13];
    tmp[6] = 0;
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[7];
    tmp[1] = product[8];
    tmp[2] = product[9];
    tmp[3] = product[10];
    tmp[4] = product[11];
    tmp[5] = product[12];
    tmp[6] = product[13];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[11];
    tmp[1] = product[12];
    tmp[2] = product[13];
    tmp[3] = tmp[4] = tmp[5] = tmp[6] = 0;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    }
    else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#endif /* uECC_WORD_SIZE */

#endif /* uECC_CURVE */
#endif /* !asm_mmod_fast */


/* Computes result = (left * right) % curve_p. */
static void vli_modMult_fast(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right) {
    uECC_word_t product[2 * uECC_WORDS];
    vli_mult(product, left, right);
    vli_mmod_fast(result, product);
}

#if uECC_SQUARE_FUNC

/* Computes result = left^2 % curve_p. */
static void vli_modSquare_fast(uECC_word_t* result, const uECC_word_t* left) {
    uECC_word_t product[2 * uECC_WORDS];
    vli_square(product, left);
    vli_mmod_fast(result, product);
}

#else /* uECC_SQUARE_FUNC */

#define vli_modSquare_fast(result, left) vli_modMult_fast((result), (left), (left))

#endif /* uECC_SQUARE_FUNC */


#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
#if !asm_modInv
static void vli_modInv(uECC_word_t* result, const uECC_word_t* input, const uECC_word_t* mod) {
    uECC_word_t a[uECC_WORDS], b[uECC_WORDS], u[uECC_WORDS], v[uECC_WORDS];
    uECC_word_t carry;
    cmpresult_t cmpResult;

    if (vli_isZero(input)) {
        vli_clear(result);
        return;
    }

    vli_set(a, input);
    vli_set(b, mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    while ((cmpResult = vli_cmp(a, b)) != 0) {
        carry = 0;
        if (EVEN(a)) {
            vli_rshift1(a);
            if (!EVEN(u)) {
                carry = vli_add(u, u, mod);
            }
            vli_rshift1(u);
            if (carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
        else if (EVEN(b)) {
            vli_rshift1(b);
            if (!EVEN(v)) {
                carry = vli_add(v, v, mod);
            }
            vli_rshift1(v);
            if (carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
        else if (cmpResult > 0) {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if (vli_cmp(u, v) < 0) {
                vli_add(u, u, mod);
            }
            vli_sub(u, u, v);
            if (!EVEN(u)) {
                carry = vli_add(u, u, mod);
            }
            vli_rshift1(u);
            if (carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
        else {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if (vli_cmp(v, u) < 0) {
                vli_add(v, v, mod);
            }
            vli_sub(v, v, u);
            if (!EVEN(v)) {
                carry = vli_add(v, v, mod);
            }
            vli_rshift1(v);
            if (carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
    }
    vli_set(result, u);
}
#endif /* !asm_modInv */


/* ------ Point operations ------ */

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
static cmpresult_t EccPoint_isZero(const EccPoint* point) {
    return (vli_isZero(point->x) && vli_isZero(point->y));
}

//point double

#if (uECC_CURVE == uECC_secp256k1)
static void point_double(uECC_word_t* X1, uECC_word_t* Y1)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS], t4[uECC_WORDS];
    int i;
    vli_clear(t1);
    vli_clear(t2);
    vli_clear(t3);
    vli_clear(t4);
    vli_modSquare_fast(t1, X1);
    vli_modAdd(t2, t1, t1, curve_p);
    vli_modAdd(t3, t1, t2, curve_p);
    vli_modAdd(t1, Y1, Y1, curve_p);
    vli_modInv(t2, t1, curve_p);
    vli_modMult_fast(t1, t3, t2);//lamda=t1
    vli_modSquare_fast(t2, t1);
    vli_modAdd(t4, X1, X1, curve_p);
    vli_modSub(t2, t2, t4, curve_p);
    vli_modSub(t3, X1, t2, curve_p);
    vli_modMult_fast(t4, t1, t3);
    vli_modSub(t3, t4, Y1, curve_p);//Y3=t3
    vli_set(X1, t2);
    vli_set(Y1, t3);
}


#else
static void point_double(uECC_word_t* X1, uECC_word_t* Y1)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS], t4[uECC_WORDS];
    int i;
    vli_clear(t1);
    vli_clear(t2);
    vli_clear(t3);
    vli_clear(t4);
    vli_modSquare_fast(t1, X1);
    vli_modAdd(t2, t1, t1, curve_p);
    vli_modAdd(t3, t1, t2, curve_p);
    vli_modAdd(t4, t3, curve_a, curve_p);
    vli_modAdd(t1, Y1, Y1, curve_p);
    vli_modInv(t2, t1, curve_p);
    vli_modMult_fast(t1, t4, t2);//lamda=t1
    vli_modSquare_fast(t2, t1);
    vli_modAdd(t4, X1, X1, curve_p);
    vli_modSub(t2, t2, t4, curve_p);
    vli_modSub(t3, X1, t2, curve_p);
    vli_modMult_fast(t4, t1, t3);
    vli_modSub(t3, t4, Y1, curve_p);//Y3=t3
    vli_set(X1, t2);
    vli_set(Y1, t3);
}

#endif


static void point_add(uECC_word_t* X1, uECC_word_t* Y1, uECC_word_t* X2, uECC_word_t* Y2)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS], t4[uECC_WORDS];
    int i;
    vli_clear(t1);
    vli_clear(t2);
    vli_clear(t3);
    vli_clear(t4);
    vli_modSub(t1, Y2, Y1, curve_p);
    vli_modSub(t2, X2, X1, curve_p);
    vli_modInv(t3, t2, curve_p);
    vli_modMult_fast(t2, t1, t3);//lamda=t2
    vli_modSquare_fast(t1, t2);
    vli_modAdd(t4, X1, X2, curve_p);
    vli_modSub(t3, t1, t4, curve_p);//X3=t3
    vli_modSub(t1, X1, t3, curve_p);
    vli_modMult_fast(t4, t1, t2);
    vli_modSub(t1, t4, Y1, curve_p);//Y3=t1
    vli_set(X1, t3);
    vli_set(Y1, t1);

}


/* Double in place */
#if (uECC_CURVE == uECC_secp256k1)
static void EccPoint_double_jacobian(uECC_word_t* RESTRICT X1,
    uECC_word_t* RESTRICT Y1,
    uECC_word_t* RESTRICT Z1) {
    /* t1 = X, t2 = Y, t3 = Z */
    uECC_word_t t4[uECC_WORDS];
    uECC_word_t t5[uECC_WORDS];

    if (vli_isZero(Z1)) {
        return;
    }

    vli_modSquare_fast(t5, Y1);   /* t5 = y1^2 */
    vli_modMult_fast(t4, X1, t5); /* t4 = x1*y1^2 = A */
    vli_modSquare_fast(X1, X1);   /* t1 = x1^2 */
    vli_modSquare_fast(t5, t5);   /* t5 = y1^4 */
    vli_modMult_fast(Z1, Y1, Z1); /* t3 = y1*z1 = z3 */

    vli_modAdd(Y1, X1, X1, curve_p); /* t2 = 2*x1^2 */
    vli_modAdd(Y1, Y1, X1, curve_p); /* t2 = 3*x1^2 */
    if (vli_testBit(Y1, 0)) {
        uECC_word_t carry = vli_add(Y1, Y1, curve_p);
        vli_rshift1(Y1);
        Y1[uECC_WORDS - 1] |= carry << (uECC_WORD_BITS - 1);
    }
    else {
        vli_rshift1(Y1);
    }
    /* t2 = 3/2*(x1^2) = B */

    vli_modSquare_fast(X1, Y1);      /* t1 = B^2 */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - A */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - 2A = x3 */

    vli_modSub(t4, t4, X1, curve_p); /* t4 = A - x3 */
    vli_modMult_fast(Y1, Y1, t4);    /* t2 = B * (A - x3) */
    vli_modSub(Y1, Y1, t5, curve_p); /* t2 = B * (A - x3) - y1^4 = y3 */
}
#else
static void EccPoint_double_jacobian(uECC_word_t* RESTRICT X1,
    uECC_word_t* RESTRICT Y1,
    uECC_word_t* RESTRICT Z1) {
    /* t1 = X, t2 = Y, t3 = Z */
    uECC_word_t t4[uECC_WORDS];
    uECC_word_t t5[uECC_WORDS];

    if (vli_isZero(Z1)) {
        return;
    }

    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub_fast(Z1, X1, Z1);     /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if (vli_testBit(X1, 0)) {
        uECC_word_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[uECC_WORDS - 1] |= l_carry << (uECC_WORD_BITS - 1);
    }
    else {
        vli_rshift1(X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */

    vli_modSquare_fast(Z1, X1);   /* t3 = B^2 */
    vli_modSub_fast(Z1, Z1, t5);  /* t3 = B^2 - A */
    vli_modSub_fast(Z1, Z1, t5);  /* t3 = B^2 - 2A = x3 */
    vli_modSub_fast(t5, t5, Z1);  /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5); /* t1 = B * (A - x3) */
    vli_modSub_fast(t4, X1, t4);  /* t4 = B * (A - x3) - y1^4 = y3 */

    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}
#endif

static void mix_affine_projective_add(uECC_word_t* RESTRICT X1, uECC_word_t* RESTRICT Y1, uECC_word_t* RESTRICT Z1, uECC_word_t* RESTRICT X2, uECC_word_t* RESTRICT Y2)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS], t4[uECC_WORDS], t5[uECC_WORDS], t6[uECC_WORDS], t7[uECC_WORDS];
    vli_set(t1, X1);
    vli_set(t2, Y1);
    vli_set(t3, Z1);
    vli_set(t4, X2);
    vli_set(t5, Y2);
    vli_modSquare_fast(t6, t3);
    vli_modMult_fast(t4, t4, t6);
    vli_modMult_fast(t5, t5, t3);
    vli_modMult_fast(t5, t5, t6);
    vli_modSub(t1, t1, t4, curve_p);
    vli_modMult_fast(t3, t1, t3);
    vli_modSub(t2, t2, t5, curve_p);
    vli_modSquare_fast(t6, t1);
    vli_modSquare_fast(t7, t2);
    vli_modMult_fast(t4, t4, t6);
    vli_modMult_fast(t1, t6, t1);
    vli_modSub(t7, t7, t1, curve_p);
    vli_modAdd(t6, t4, t4, curve_p);
    vli_modSub(t7, t7, t6, curve_p);
    vli_modSub(t4, t4, t7, curve_p);
    vli_modMult_fast(t2, t2, t4);
    vli_modMult_fast(t6, t5, t1);
    vli_modSub(t6, t2, t6, curve_p);
    vli_set(X1, t7);
    vli_set(Y1, t6);
    vli_set(Z1, t3);
}

static void point_add_projective(uECC_word_t* X1, uECC_word_t* Y1, uECC_word_t* Z1, uECC_word_t* X2, uECC_word_t* Y2, uECC_word_t* Z2)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS], t4[uECC_WORDS], t5[uECC_WORDS], t6[uECC_WORDS], t7[uECC_WORDS];
    vli_set(t1, X1);
    vli_set(t2, Y1);
    vli_set(t3, Z1);
    vli_set(t4, X2);
    vli_set(t5, Y2);
    vli_set(t6, Z2);
    vli_modSquare_fast(t7, t3);
    vli_modMult_fast(t4, t4, t7);
    vli_modMult_fast(t5, t5, t3);
    vli_modMult_fast(t5, t5, t7);
    vli_modSquare_fast(t7, t6);
    vli_modMult_fast(t1, t1, t7);
    vli_modMult_fast(t2, t2, t6);
    vli_modMult_fast(t2, t2, t7);
    vli_modSub(t1, t1, t4, curve_p);
    vli_modMult_fast(t3, t6, t3);
    vli_modMult_fast(t3, t1, t3);
    vli_modSub(t2, t2, t5, curve_p);
    vli_modSquare_fast(t7, t1);
    vli_modSquare_fast(t6, t2);
    vli_modMult_fast(t4, t4, t7);
    vli_modMult_fast(t1, t7, t1);
    vli_modSub(t6, t6, t1, curve_p);
    vli_modAdd(t7, t4, t4, curve_p);
    vli_modSub(t6, t6, t7, curve_p);
    vli_modSub(t4, t4, t6, curve_p);
    vli_modMult_fast(t2, t2, t4);
    vli_modMult_fast(t7, t5, t1);
    vli_modSub(t7, t2, t7, curve_p);
    vli_set(X1, t6);
    vli_set(Y1, t7);
    vli_set(Z1, t3);

}


static void recover_z(uECC_word_t* RESTRICT X0, uECC_word_t* RESTRICT Y0, uECC_word_t* RESTRICT X1, uECC_word_t* RESTRICT Y1, uECC_word_t* RESTRICT Z1)
{
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS], t3[uECC_WORDS];
    vli_modInv(t1, Z1, curve_p);
    vli_modSquare_fast(t2, t1);
    vli_modMult_fast(t3, t1, t2);
    vli_modMult_fast(X0, X1, t2);
    vli_modMult_fast(Y0, Y1, t3);
}
static void apply_z(uECC_word_t* RESTRICT X1,
    uECC_word_t* RESTRICT Y1,
    const uECC_word_t* RESTRICT Z) {
    uECC_word_t t1[uECC_WORDS];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

#if (uECC_CURVE == uECC_secp160r1)
static void windows_algorithm_4_projective(EccPoint* result, EccPoint* point, uECC_word_t* scalar, bitcount_t numBits)
{
    uECC_word_t pre_G[30][uECC_WORDS] = {
    {0x13CBFC82, 0x68C38BB9, 0x46646989, 0x8EF57328, 0x4A96B568 }, \
    {0x7AC5FB32, 0x04235137, 0x59DCC912, 0x3168947D, 0x23A62855 },\
    {0xe8f46686, 0x675d3e92, 0x55d3edf8, 0x3c5ed04c, 0x2f997f3 },\
    {0x7df8797b, 0x21cfb773, 0x440e817e, 0x482993e9, 0xf083a323 }, \
    {0xa958bc59, 0x50bd48da, 0xdf13de16, 0x1ef363f2, 0x7b76ff54 }, \
    {0xfe9f6f5a, 0x9d12854f, 0xb55be007, 0xd8c8877, 0xc915ca79 },\
    {0xcf2a88, 0x7b1ad4c1, 0xafe01c30, 0x83be99f0, 0xb4041d86 },\
    {0xf9beed08, 0xcaf4a5bc, 0x660cc74, 0x841f08c0, 0x3f32caed },\
    {0x3ad6c4e, 0x424c1713, 0x772d1e2d, 0xe41192ed, 0xe705b180 },\
    {0x64b2a59c, 0xa12b5833, 0x465dbf40, 0x78c8c01, 0x933fbe35 },\
    {0xac3a397e, 0xa006b15d, 0xd524362b, 0x209f5a76, 0xeb0570b9 },\
    {0x35338a6, 0x2049a5fa, 0x4ff1cab1, 0x83d22f11, 0x136df966 },\
    {0x61472188, 0x9b3a35e9, 0x577c4e8c, 0x6472f619, 0x7a7f99d5 },\
    {0x2552e356, 0xee00fae6, 0x673c6d55, 0x4aa7b3ca, 0x8955c17a },\
    {0x88329f1b, 0x8df4fb38, 0x70d6eb7f, 0x79c51227, 0x87311d3d },\
    {0x3c87eea6, 0xa27eabba, 0x6b2b507a, 0x39306262, 0xf785e0ff },\
    {0x64d93bbb, 0x31e3f006, 0xf8142cf7, 0x8e2b7b5d, 0x25393e4 },\
    {0x54694156, 0xe7b973a9, 0x233f23a2, 0x76185c0d, 0xe75de5df },\
    {0x7580d645, 0x93bf92c4, 0x279d2fd2, 0x2ccc8511, 0xffa7ace3 },\
    {0x223bcaaf, 0x23d9f1de, 0x7f1e6ab5, 0x3311674d, 0x4b3a0b0c },\
    {0x9c4e8282, 0xe0386972, 0x330549cc, 0xd6319896, 0x919a63e6 },\
    {0x946efe31, 0xa6bdf008, 0xd7ecd3bd, 0xde750423, 0x7ef14d9e },\
    {0x708ade0a, 0x182f2b39, 0x8383b96a, 0x5cbdde71, 0xbd002d60 },\
    {0x948f5e17, 0x295b8774, 0xda82664e, 0x514165d2, 0xb8888222},\
    {0xeaeb1efc, 0x89f5aea0, 0xaef9708e, 0x6f4ac25, 0x205b91a2 },\
    {0x98cc9351, 0x9527c953, 0x64431374, 0xbc6fd424, 0xc7c429aa },\
    {0xe2f4b87c, 0x805e5a, 0x2130d5bf, 0x66688701, 0x36720e67 },\
    {0x2f92f2e2, 0x58eb3a7c, 0x5a618337, 0x1faead28, 0xe205a3a5 },\
    {0x98012168, 0x830d92cf, 0xdd34165e, 0x3fb143ea, 0x7da67ee8 },\
    {0x5a47df72, 0xc064c54f, 0xd28493c3, 0xee4f1e62, 0x8bd0120a }

    };
    uECC_word_t result_x[2][uECC_WORDS], result_y[2][uECC_WORDS], result_z[2][uECC_WORDS];
    uECC_word_t  d;
    int i, j, nb;
    d = vli_testBit_1(scalar, numBits - 1);
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[1][i] = pre_G[2 * (d - 1)][i];
        result_y[1][i] = pre_G[2 * (d - 1) + 1][i];
    }
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[0][i] = pre_G[2 * (d - 1)][i];
        result_y[0][i] = pre_G[2 * (d - 1) + 1][i];
    }
    vli_clear(result_z[1]);
    result_z[1][0] = 1;
    vli_clear(result_z[0]);
    result_z[0][0] = 1;
    for (i = numBits - 2; i >= 0; i--)
    {
        d = vli_testBit_1(scalar, i);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        nb = !!d;
        mix_affine_projective_add(result_x[nb], result_y[nb], result_z[nb], pre_G[2 * (d - 1) * nb], pre_G[(2 * (d - 1) + 1) * nb]);
    }
    recover_z(result->x, result->y, result_x[1], result_y[1], result_z[1]);
}

#elif (uECC_CURVE == uECC_secp256k1)

static void windows_algorithm_4_projective(EccPoint* result, EccPoint* point, uECC_word_t* scalar, bitcount_t numBits)
{
    uECC_word_t pre_G[30][uECC_WORDS] = {
        {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E }, \
 {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77 },\
 {0x5c709ee5, 0xabac09b9, 0x8cef3ca7, 0x5c778e4b, 0x95c07cd8, 0x3045406e, 0x41ed7d6d, 0xc6047f94 },\
 {0x50cfe52a, 0x236431a9, 0x3266d0e1, 0xf7f63265, 0x466ceaee, 0xa3c58419, 0xa63dc339, 0x1ae168fe }, \
 {0xbce036f9, 0x8601f113, 0x836f99b0, 0xb531c845, 0xf89d5229, 0x49344f85, 0x9258c310, 0xf9308a01 }, \
 {0x84b8e672, 0x6cb9fd75, 0x34c2231b, 0x6500a999, 0x2a37f356, 0xfe337e6, 0x632de814, 0x388f7b0f },\
 {0xe8c4cd13, 0x74fa94ab, 0xee07584, 0xcc6c1390, 0x930b1404, 0x581e4904, 0xc10d80f3, 0xe493dbf1 },\
 {0x47739922, 0xcfe97bdc, 0xbfbdfe40, 0xd967ae33, 0x8ea51448, 0x5642e209, 0xa0d455b7, 0x51ed993e },\
 {0xb240efe4, 0xcba8d569, 0xdc619ab7, 0xe88b84bd, 0xa5c5128, 0x55b4a725, 0x1a072093, 0x2f8bde4d },\
 {0xa6ac62d6, 0xdca87d3a, 0xab0d6840, 0xf788271b, 0xa6c9c426, 0xd4dba9dd, 0x36e5e3d6, 0xd8ac2226 },\
 {0x60297556, 0x2f057a14, 0x8568a18b, 0x82f6472f, 0x355235d3, 0x20453a14, 0x755eeea4, 0xfff97bd5 },\
 {0xb075f297, 0x3c870c36, 0x518fe4a0, 0xde80f0f6, 0x7f45c560, 0xf3be9601, 0xacfbb620, 0xae12777a },\
 {0xcac4f9bc, 0xe92bdded, 0x330e39c, 0x3d419b7e, 0xf2ea7a0e, 0xa398f365, 0x6e5db4ea, 0x5cbdf064 },\
 {0x87264da, 0xa5082628, 0x13fde7b5, 0xa813d0b8, 0x861a54db, 0xa3178d6d, 0xba255960, 0x6aebca40 },\
 {0xe10a2a01, 0x67784ef3, 0xe5af888a, 0xa1bdd05, 0xb70f3c2f, 0xaff3843f, 0x5cca351d, 0x2f01e5e1 },\
 {0x6cbde904, 0xb5da2cb7, 0xba5b7617, 0xc2e213d6, 0x132d13b4, 0x293d082a, 0x41539949, 0x5c4da8a7 },\
 {0xfc27ccbe, 0xc35f110d, 0x4c57e714, 0xe0979697, 0x9f559abd, 0x9ad178a, 0xf0c7f653, 0xacd484e2 },\
 {0xc64f9c37, 0x5cc262a, 0x375f8e0f, 0xadd888a4, 0x763b61e9, 0x64380971, 0xb0a7d9fd, 0xcc338921 },\
 {0x47e247c7, 0x52a68e2a, 0x1943c2b7, 0x3442d49b, 0x1ae6ae5d, 0x35477c7b, 0x47f3c862, 0xa0434d9e },\
 {0x37368d7, 0x3cbee53b, 0xd877a159, 0x6f794c2e, 0x93a24c69, 0xa3b6c7e6, 0x5419bc27, 0x893aba42 },\
 {0x5da008cb, 0xbbec1789, 0xe5c17891, 0x5649980b, 0x70c65aac, 0x5ef4246b, 0x58a9411e, 0x774ae7f8 },\
 {0xc953c61b, 0x301d74c9, 0xdff9d6a8, 0x372db1e2, 0xd7b7b365, 0x243dd56, 0xeb6b5e19, 0xd984a032 },\
 {0x70afe85a, 0xc5b0f470, 0x9620095b, 0x687cf441, 0x4d734633, 0x15c38f00, 0x48e7561b, 0xd01115d5 },\
 {0xf4062327, 0x6b051b13, 0xd9a86d52, 0x79238c5d, 0xe17bd815, 0xa8b64537, 0xc815e0d7, 0xa9f34ffd },\
 {0x19405aa8, 0xdeeddf8f, 0x610e58cd, 0xb075fbc6, 0xc3748651, 0xc7d1d205, 0xd975288b, 0xf28773c2 },\
 {0xdb03ed81, 0x29b5cb52, 0x521fa91f, 0x3a1a06da, 0x65cdaf47, 0x758212eb, 0x8d880a89, 0xab0902e },\
 {0x60e823e4, 0xe49b241a, 0x678949e6, 0x26aa7b63, 0x7d38e32, 0xfd64e67f, 0x895e719c, 0x499fdf9e },\
 {0x3a13f5b, 0xc65f40d4, 0x7a3f95bc, 0x464279c2, 0xa7b3d464, 0x90f044e4, 0xb54e8551, 0xcac2f6c4 },\
 {0xe27e080e, 0x44adbcf8, 0x3c85f79e, 0x31e5946f, 0x95ff411, 0x5a465ae3, 0x7d43ea96, 0xd7924d4f },\
 {0xf6a26b58, 0xc504dc9f, 0xd896d3a5, 0xea40af2b, 0x28cc6def, 0x83842ec2, 0xa86c72a6, 0x581e2872 }

    };
    uECC_word_t result_x[2][uECC_WORDS], result_y[2][uECC_WORDS], result_z[2][uECC_WORDS];
    uECC_word_t  d;
    int i, j, nb;
    d = vli_testBit_1(scalar, numBits - 1);
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[1][i] = pre_G[2 * (d - 1)][i];
        result_y[1][i] = pre_G[2 * (d - 1) + 1][i];
    }
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[0][i] = pre_G[2 * (d - 1)][i];
        result_y[0][i] = pre_G[2 * (d - 1) + 1][i];
    }
    vli_clear(result_z[1]);
    result_z[1][0] = 1;
    vli_clear(result_z[0]);
    result_z[0][0] = 1;
    for (i = numBits - 2; i >= 0; i--)
    {
        d = vli_testBit_1(scalar, i);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        nb = !!d;
        mix_affine_projective_add(result_x[nb], result_y[nb], result_z[nb], pre_G[2 * (d - 1) * nb], pre_G[(2 * (d - 1) + 1) * nb]);
    }
    recover_z(result->x, result->y, result_x[1], result_y[1], result_z[1]);
}


#elif (uECC_CURVE == uECC_secp192r1)

static void windows_algorithm_4_projective(EccPoint* result, EccPoint* point, uECC_word_t* scalar, bitcount_t numBits)
{
    uECC_word_t pre_G[30][uECC_WORDS] = {
    {0x82FF1012, 0xF4FF0AFD, 0x43A18800, 0x7CBF20EB, 0xB03090F6, 0x188DA80E }, \
 {0x1E794811, 0x73F977A1, 0x6B24CDD5, 0x631011ED, 0xFFC8DA78, 0x07192B95 },\
 {0x6982a888, 0x29a70fb1, 0x1588a3f6, 0xd3553463, 0x28783f2a, 0xdafebf58 },\
 {0x5c7e93ab, 0x59331afa, 0x141b868f, 0x46b27bbc, 0x993da0fa, 0xdd6bda0d }, \
 {0xcbb263da, 0xdfd0d359, 0x1fb2b9aa, 0xdcd28320, 0x57599e6e, 0x76e32a25 }, \
 {0xcfd05fd, 0xf3b54366, 0xd121d49e, 0xaa62e0fe, 0x72ba4520, 0x782c37e3 },\
 {0x7084e4ba, 0xa4fe4664, 0x374729d7, 0xb0015703, 0x297cc378, 0x35433907 },\
 {0x1db3be32, 0x25389b31, 0x776cd4f1, 0x1ea3acb0, 0xf2135c30, 0xa2649984 },\
 {0xdd7ff590, 0x590118eb, 0x300e1605, 0x3e078d9c, 0x40049b18, 0x10bb8e98 },\
 {0x3cceaea1, 0x312b7254, 0xe62762be, 0xadc9f836, 0x476f917b, 0x31361008 },\
 {0x93d23f2a, 0xace8ecb, 0xaa667832, 0x98bf5bd1, 0x431f9ac3, 0xa37abc6c },\
 {0x10bc68f0, 0x81f7c57, 0x1bbda90e, 0xfed7040a, 0xc99908db, 0x851b3cae },\
 {0x7011fcfd, 0x5de37f00, 0x3060edce, 0x60f92324, 0x75ddcd76, 0x8da75a1f },\
 {0x6409ffb5, 0xd4b702f9, 0xfdb3c01d, 0x18240db8, 0x6860b354, 0x57cb5fcf },\
 {0x3397edde, 0x4b597788, 0xcc14899d, 0x14771993, 0x1ecce920, 0x2fa1f92d },\
 {0x9738f6c0, 0xf2dd8a8e, 0x78ef733f, 0x273b8b59, 0xf78b7214, 0xa338afde },\
 {0xb980388f, 0x1d9d375a, 0xa8d27c9e, 0x4e9e8f2b, 0x8b1cabb7, 0x818a4d30 },\
 {0x76c8e739, 0x30ea5421, 0xbb457cdf, 0x7c292f7c, 0x208d87cd, 0x1d1aa5e },\
 {0xd1fe9d85, 0x859bb150, 0xd9238842, 0xd1aede2b, 0xf99e3e96, 0xaa7c4f9e },\
 {0x491397b0, 0x60eb5eb2, 0xb2f48594, 0x1ee3658, 0x47edc629, 0x3212a365 },\
 {0x628a2aa, 0x28094037, 0x4d22b652, 0x1844f716, 0xeb76324f, 0x1c995995 },\
 {0x1aaa9c04, 0xb34cb861, 0xfa77bd, 0x29f5564, 0x37e9eb73, 0xef1765ce },\
 {0x67eeb8ab, 0x8fccdcda, 0xf8c9e7b2, 0xca013877, 0x3d456d0e, 0x1061343f },\
 {0xb27293f, 0x681eac02, 0xe7a48648, 0x98fef8e3, 0x2ea6b037, 0x5a064caa },\
 {0x3c4a090a, 0x4144a36, 0x51e4ea0, 0x2f68821e, 0xd33efb9f, 0x112af141 },\
 {0x432b1c1e, 0x7f10a094, 0xe081e09e, 0x2a2c1726, 0xfc5293f7, 0x6e0cbe3b },\
 {0xde1081c1, 0xdee08843, 0xf7c64e05, 0x591746b3, 0x46ebc93b, 0x13b93106 },\
 {0xe186e6b4, 0x4fbaca95, 0xec41a1ec, 0x15f3b427, 0xb44142dd, 0x1edcea63 },\
 {0x7578b1e7, 0x36de4a9e, 0xb5414de7, 0xba3546b2, 0x3b56b633, 0x8c9595e6 },\
 {0xd98fc7b1, 0xad7537cd, 0x3aa566b6, 0x7cf38799, 0x934f00c1, 0x266b762a }

    };
    uECC_word_t result_x[2][uECC_WORDS], result_y[2][uECC_WORDS], result_z[2][uECC_WORDS];
    uECC_word_t  d;
    int i, j, nb;
    d = vli_testBit_1(scalar, numBits - 1);
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[1][i] = pre_G[2 * (d - 1)][i];
        result_y[1][i] = pre_G[2 * (d - 1) + 1][i];
    }
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[0][i] = pre_G[2 * (d - 1)][i];
        result_y[0][i] = pre_G[2 * (d - 1) + 1][i];
    }
    vli_clear(result_z[1]);
    result_z[1][0] = 1;
    vli_clear(result_z[0]);
    result_z[0][0] = 1;
    for (i = numBits - 2; i >= 0; i--)
    {
        d = vli_testBit_1(scalar, i);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        nb = !!d;
        mix_affine_projective_add(result_x[nb], result_y[nb], result_z[nb], pre_G[2 * (d - 1) * nb], pre_G[(2 * (d - 1) + 1) * nb]);
    }
    recover_z(result->x, result->y, result_x[1], result_y[1], result_z[1]);
}

#endif


static void windows_algorithm_4_projective_pre(EccPoint* result, EccPoint* point, uECC_word_t* scalar, bitcount_t numBits)
{
    //pre-compute
    uECC_word_t pre_G[45][uECC_WORDS], z[uECC_WORDS];
    EccPoint temp_1, temp_2;
    vli_set(temp_1.x, point->x);
    vli_set(temp_1.y, point->y);
    vli_set(temp_2.x, point->x);
    vli_set(temp_2.y, point->y);
    vli_clear(z);
    z[0] = 0x1;
    vli_set(pre_G[0], temp_2.x);
    vli_set(pre_G[1], temp_2.y);
    vli_set(pre_G[2], z);
    EccPoint_double_jacobian(temp_1.x, temp_1.y, z);
    vli_set(pre_G[3], temp_1.x);
    vli_set(pre_G[4], temp_1.y);
    vli_set(pre_G[5], z);
    int i, nb;
    for (i = 2;i < 15;i++)
    {
        mix_affine_projective_add(temp_1.x, temp_1.y, z, temp_2.x, temp_2.y);
        vli_set(pre_G[3 * i], temp_1.x);
        vli_set(pre_G[3 * i + 1], temp_1.y);
        vli_set(pre_G[3 * i + 2], z);
    }
    //scalar mutiplication
    uECC_word_t result_x[2][uECC_WORDS], result_y[2][uECC_WORDS], result_z[2][uECC_WORDS];
    uECC_word_t  d;
    d = vli_testBit_1(scalar, numBits - 1);
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[1][i] = pre_G[3 * (d - 1)][i];
        result_y[1][i] = pre_G[3 * (d - 1) + 1][i];
        result_z[1][i] = pre_G[3 * (d - 1) + 2][i];

    }
    for (i = 0; i < uECC_WORDS; i++)
    {
        result_x[0][i] = pre_G[2 * (d - 1)][i];
        result_y[0][i] = pre_G[2 * (d - 1) + 1][i];
        result_z[0][i] = pre_G[3 * (d - 1) + 2][i];
    }

    for (i = numBits - 2; i >= 0; i--)
    {
        d = vli_testBit_1(scalar, i);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        EccPoint_double_jacobian(result_x[1], result_y[1], result_z[1]);
        nb = !!d;
        point_add_projective(result_x[nb], result_y[nb], result_z[nb], pre_G[3 * (d - 1) * nb], pre_G[(3 * (d - 1) + 1) * nb], pre_G[(3 * (d - 1) + 2) * nb]);
    }
    recover_z(result->x, result->y, result_x[1], result_y[1], result_z[1]);


}


#if uECC_WORD_SIZE == 1

static void vli_nativeToBytes(uint8_t* RESTRICT dest, const uint8_t* RESTRICT src) {
    uint8_t i;
    for (i = 0; i < uECC_BYTES; ++i) {
        dest[i] = src[(uECC_BYTES - 1) - i];
    }
}

#define vli_bytesToNative(dest, src) vli_nativeToBytes((dest), (src))

#elif uECC_WORD_SIZE == 4

static void vli_nativeToBytes(uint8_t* bytes, const uint32_t* native) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uint8_t* digit = bytes + 4 * (uECC_WORDS - 1 - i);
        digit[0] = native[i] >> 24;
        digit[1] = native[i] >> 16;
        digit[2] = native[i] >> 8;
        digit[3] = native[i];
    }
}

static void vli_bytesToNative(uint32_t* native, const uint8_t* bytes) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        const uint8_t* digit = bytes + 4 * (uECC_WORDS - 1 - i);
        native[i] = ((uint32_t)digit[0] << 24) | ((uint32_t)digit[1] << 16) |
            ((uint32_t)digit[2] << 8) | (uint32_t)digit[3];
    }
}

#else

static void vli_nativeToBytes(uint8_t* bytes, const uint64_t* native) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uint8_t* digit = bytes + 8 * (uECC_WORDS - 1 - i);
        digit[0] = native[i] >> 56;
        digit[1] = native[i] >> 48;
        digit[2] = native[i] >> 40;
        digit[3] = native[i] >> 32;
        digit[4] = native[i] >> 24;
        digit[5] = native[i] >> 16;
        digit[6] = native[i] >> 8;
        digit[7] = native[i];
    }
}

static void vli_bytesToNative(uint64_t* native, const uint8_t* bytes) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        const uint8_t* digit = bytes + 8 * (uECC_WORDS - 1 - i);
        native[i] = ((uint64_t)digit[0] << 56) | ((uint64_t)digit[1] << 48) |
            ((uint64_t)digit[2] << 40) | ((uint64_t)digit[3] << 32) |
            ((uint64_t)digit[4] << 24) | ((uint64_t)digit[5] << 16) |
            ((uint64_t)digit[6] << 8) | (uint64_t)digit[7];
    }
}

#endif /* uECC_WORD_SIZE */

static int EccPoint_compute_public_key(EccPoint* result, uECC_word_t* private) {

    windows_algorithm_4_projective(result, &curve_G, private, vli_numBits_1(private, uECC_WORDS));

}

int uECC_compute_public_key_wp(const uint8_t private_key[uECC_BYTES],
    uint8_t public_key[uECC_BYTES * 2]) {
    uECC_word_t private[uECC_WORDS];
    EccPoint public;

    vli_bytesToNative(private, private_key);
    if (!EccPoint_compute_public_key(&public, private)) {
        return 0;
    }
    vli_nativeToBytes(public_key, public.x);
    vli_nativeToBytes(public_key + uECC_BYTES, public.y);
    return 1;

}

void uECC_point_add_wp(uint8_t X1[uECC_BYTES], uint8_t Y1[uECC_BYTES], uint8_t X2[uECC_BYTES], uint8_t Y2[uECC_BYTES])
{
    uECC_word_t x1[uECC_WORDS], y1[uECC_WORDS], x2[uECC_WORDS], y2[uECC_WORDS];
    vli_bytesToNative(x1, X1);
    vli_bytesToNative(y1, Y1);
    vli_bytesToNative(x2, X2);
    vli_bytesToNative(y2, Y2);
    point_add(x1, y1, x2, y2);

    vli_nativeToBytes(X1, x1);
    vli_nativeToBytes(Y1, y1);

}


int uECC_shared_secret_wp(const uint8_t public_key[uECC_BYTES * 2],
    const uint8_t private_key[uECC_BYTES],
    uint8_t secret[uECC_BYTES * 2])
{
    EccPoint public;
    EccPoint product;
    uECC_word_t private[uECC_WORDS];
    vli_bytesToNative(private, private_key);
    vli_bytesToNative(public.x, public_key);
    vli_bytesToNative(public.y, public_key + uECC_BYTES);

    windows_algorithm_4_projective_pre(&product, &public, private, vli_numBits_1(private, uECC_WORDS));

    vli_nativeToBytes(secret, product.x);
    vli_nativeToBytes(secret + uECC_BYTES, product.y);

    return 1;
}



// n operation
#if (uECC_CURVE == uECC_secp160r1)
static void vli_clear_n(uECC_word_t* vli) {
    vli_clear(vli);
    vli[uECC_N_WORDS - 1] = 0;
}

static uECC_word_t vli_isZero_n(const uECC_word_t* vli) {
    if (vli[uECC_N_WORDS - 1]) {
        return 0;
    }
    return vli_isZero(vli);
}

static void vli_set_n(uECC_word_t* dest, const uECC_word_t* src) {
    vli_set(dest, src);
    dest[uECC_N_WORDS - 1] = src[uECC_N_WORDS - 1];
}


static cmpresult_t vli_cmp_n(const uECC_word_t* left, const uECC_word_t* right) {
    if (left[uECC_N_WORDS - 1] > right[uECC_N_WORDS - 1]) {
        return 1;
    }
    else if (left[uECC_N_WORDS - 1] < right[uECC_N_WORDS - 1]) {
        return -1;
    }
    return vli_cmp(left, right);
}

static void vli_rshift1_n(uECC_word_t* vli) {
    vli_rshift1(vli);
    vli[uECC_N_WORDS - 2] |= vli[uECC_N_WORDS - 1] << (uECC_WORD_BITS - 1);
    vli[uECC_N_WORDS - 1] = vli[uECC_N_WORDS - 1] >> 1;
}

static uECC_word_t vli_add_n(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right) {
    uECC_word_t carry = vli_add(result, left, right);
    uECC_word_t sum = left[uECC_N_WORDS - 1] + right[uECC_N_WORDS - 1] + carry;
    if (sum != left[uECC_N_WORDS - 1]) {
        carry = (sum < left[uECC_N_WORDS - 1]);
    }
    result[uECC_N_WORDS - 1] = sum;
    return carry;
}

static uECC_word_t vli_sub_n(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right) {
    uECC_word_t borrow = vli_sub(result, left, right);
    uECC_word_t diff = left[uECC_N_WORDS - 1] - right[uECC_N_WORDS - 1] - borrow;
    if (diff != left[uECC_N_WORDS - 1]) {
        borrow = (diff > left[uECC_N_WORDS - 1]);
    }
    result[uECC_N_WORDS - 1] = diff;
    return borrow;
}

#if !muladd_exists
static void muladd(uECC_word_t a,
    uECC_word_t b,
    uECC_word_t* r0,
    uECC_word_t* r1,
    uECC_word_t* r2) {
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
}
#define muladd_exists 1
#endif

static void vli_mult_n(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    for (k = 0; k < uECC_N_WORDS * 2 - 1; ++k) {
        wordcount_t min = (k < uECC_N_WORDS ? 0 : (k + 1) - uECC_N_WORDS);
        wordcount_t max = (k < uECC_N_WORDS ? k : uECC_N_WORDS - 1);
        for (i = min; i <= max; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_N_WORDS * 2 - 1] = r0;
}

static void vli_modAdd_n(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right,
    const uECC_word_t* mod) {
    uECC_word_t carry = vli_add_n(result, left, right);
    if (carry || vli_cmp_n(result, mod) >= 0) {
        vli_sub_n(result, result, mod);
    }
}



static void vli2_rshift1_n(uECC_word_t* vli) {
    vli_rshift1_n(vli);
    vli[uECC_N_WORDS - 1] |= vli[uECC_N_WORDS] << (uECC_WORD_BITS - 1);
    vli_rshift1_n(vli + uECC_N_WORDS);
}

static uECC_word_t vli2_sub_n(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_N_WORDS * 2; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}

/* Computes result = (left * right) % curve_n. */
static void vli_modMult_n(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    bitcount_t i;
    uECC_word_t product[2 * uECC_N_WORDS];
    uECC_word_t modMultiple[2 * uECC_N_WORDS];
    uECC_word_t tmp[2 * uECC_N_WORDS];
    uECC_word_t* v[2] = { tmp, product };
    uECC_word_t index = 1;

    vli_mult_n(product, left, right);
    vli_clear_n(modMultiple);
    vli_set(modMultiple + uECC_N_WORDS + 1, curve_n);
    vli_rshift1(modMultiple + uECC_N_WORDS + 1);
    modMultiple[2 * uECC_N_WORDS - 1] |= HIGH_BIT_SET;
    modMultiple[uECC_N_WORDS] = HIGH_BIT_SET;

    for (i = 0;
        i <= ((((bitcount_t)uECC_N_WORDS) << uECC_WORD_BITS_SHIFT) + (uECC_WORD_BITS - 1));
        ++i) {
        uECC_word_t borrow = vli2_sub_n(v[1 - index], v[index], modMultiple);
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vli2_rshift1_n(modMultiple);
    }
    vli_set_n(result, v[index]);
}

#else

#define vli_cmp_n vli_cmp
#define vli_modInv_n vli_modInv
#define vli_modAdd_n vli_modAdd

static void vli2_rshift1(uECC_word_t* vli) {
    vli_rshift1(vli);
    vli[uECC_WORDS - 1] |= vli[uECC_WORDS] << (uECC_WORD_BITS - 1);
    vli_rshift1(vli + uECC_WORDS);
}

static uECC_word_t vli2_sub(uECC_word_t* result,
    const uECC_word_t* left,
    const uECC_word_t* right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS * 2; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}

/* Computes result = (left * right) % curve_n. */
static void vli_modMult_n(uECC_word_t* result, const uECC_word_t* left, const uECC_word_t* right) {
    uECC_word_t product[2 * uECC_WORDS];
    uECC_word_t modMultiple[2 * uECC_WORDS];
    uECC_word_t tmp[2 * uECC_WORDS];
    uECC_word_t* v[2] = { tmp, product };
    bitcount_t i;
    uECC_word_t index = 1;

    vli_mult(product, left, right);
    vli_set(modMultiple + uECC_WORDS, curve_n); /* works if curve_n has its highest bit set */
    vli_clear(modMultiple);

    for (i = 0; i <= uECC_BYTES * 8; ++i) {
        uECC_word_t borrow = vli2_sub(v[1 - index], v[index], modMultiple);
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vli2_rshift1(modMultiple);
    }
    vli_set(result, v[index]);
}
#endif /* (uECC_CURVE != uECC_secp160r1) */


#if (uECC_CURVE == uECC_secp160r1)

void uECC_n_operation_wp(uint8_t result[uECC_BYTES], uint8_t HASH[uECC_BYTES], uint8_t A[uECC_BYTES], uint8_t B[uECC_BYTES])
{
    uECC_word_t res[uECC_WORDS], hash[uECC_WORDS], a[uECC_WORDS], b[uECC_WORDS];
    vli_bytesToNative(a, A);
    vli_bytesToNative(b, B);
    vli_bytesToNative(hash, HASH);
    uECC_word_t temp_1[uECC_N_WORDS], temp_5[uECC_N_WORDS], temp_6[uECC_N_WORDS];
    int i;
    for (i = 0;i < 5;i++)
    {
        temp_5[i] = hash[i];
    }
    temp_5[5] = 0;

    for (i = 0;i < 5;i++)
    {
        temp_6[i] = a[i];
    }
    temp_6[5] = 0;

    vli_modMult_n(temp_1, temp_5, temp_6);
    uECC_word_t temp_2[uECC_N_WORDS], temp_3[uECC_N_WORDS];
    for (i = 0;i < 5;i++)
    {
        temp_2[i] = b[i];
    }
    temp_2[5] = 0;
    vli_modAdd_n(temp_3, temp_1, temp_2, curve_n);
    for (i = 0;i < 5;i++)
    {
        res[i] = temp_3[i];
    }
    vli_nativeToBytes(result, res);
}


#else
void uECC_n_operation_wp(uint8_t result[uECC_BYTES], uint8_t HASH[uECC_BYTES], uint8_t A[uECC_BYTES], uint8_t B[uECC_BYTES])
{
    uECC_word_t res[uECC_WORDS], hash[uECC_WORDS], a[uECC_WORDS], b[uECC_WORDS];
    vli_bytesToNative(a, A);
    vli_bytesToNative(b, B);
    vli_bytesToNative(hash, HASH);
    uECC_word_t temp[uECC_WORDS];
    vli_modMult_n(temp, hash, a);
    vli_modAdd_n(res, temp, b, curve_n);
    vli_nativeToBytes(result, res);

}

#endif
