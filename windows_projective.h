/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _MICRO_ECC_H_
#define _MICRO_ECC_H_

#include <stdint.h>

typedef uint32_t uECC_word_t;
#if __STDC_VERSION__ >= 199901L
#define RESTRICT restrict
#else
#define RESTRICT
#endif

/* Platform selection options.
If uECC_PLATFORM is not defined, the code will try to guess it based on compiler macros.
Possible values for uECC_PLATFORM are defined below: */
#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_avr        5
#define uECC_arm_thumb2 6

/* If desired, you can define uECC_WORD_SIZE as appropriate for your platform (1, 4, or 8 bytes).
If uECC_WORD_SIZE is not explicitly defined then it will be automatically set based on your
platform. */

/* Inline assembly options.
uECC_asm_none  - Use standard C99 only.
uECC_asm_small - Use GCC inline assembly for the target platform (if available), optimized for
                 minimum size.
uECC_asm_fast  - Use GCC inline assembly optimized for maximum speed. */
#define uECC_asm_none  0
#define uECC_asm_small 1
#define uECC_asm_fast  2
#ifndef uECC_ASM
#define uECC_ASM uECC_asm_fast
#endif

/* Curve selection options. */
#define uECC_secp160r1 1
#define uECC_secp192r1 2
#define uECC_secp256r1 3
#define uECC_secp256k1 4
#define uECC_secp224r1 5
#ifndef uECC_CURVE
#define uECC_CURVE uECC_secp160r1
#endif

/* uECC_SQUARE_FUNC - If enabled (defined as nonzero), this will cause a specific function to be
used for (scalar) squaring instead of the generic multiplication function. This will make things
faster by about 8% but increases the code size. */
#ifndef uECC_SQUARE_FUNC
#define uECC_SQUARE_FUNC 1
#endif

#define uECC_CONCAT1(a, b) a##b
#define uECC_CONCAT(a, b) uECC_CONCAT1(a, b)

#define uECC_size_1 20 /* secp160r1 */
#define uECC_size_2 24 /* secp192r1 */
#define uECC_size_3 32 /* secp256r1 */
#define uECC_size_4 32 /* secp256k1 */
#define uECC_size_5 28 /* secp224r1 */

#define uECC_BYTES uECC_CONCAT(uECC_size_, uECC_CURVE)


#ifdef __cplusplus
extern "C"
{
#endif

    /* uECC_RNG_Function type
    The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
    'dest' was filled with random data, or 0 if the random data could not be generated.
    The filled-in values should be either truly random, or from a cryptographically-secure PRNG.
    A correctly functioning RNG function must be set (using uECC_set_rng()) before calling
    uECC_make_key() or uECC_sign().
    Setting a correctly functioning RNG function improves the resistance to side-channel attacks
    for uECC_shared_secret() and uECC_sign_deterministic().
    A correct RNG function is set by default when building for Windows, Linux, or OS X.
    If you are building on another POSIX-compliant system that supports /dev/random or /dev/urandom,
    you can define uECC_POSIX to use the predefined RNG. For embedded platforms there is no predefined
    RNG function; you must provide your own.
    */


    /* uECC_make_key() function.
    Create a public/private key pair.
    Outputs:
        public_key  - Will be filled in with the public key.
        private_key - Will be filled in with the private key.
    Returns 1 if the key pair was generated successfully, 0 if an error occurred.
    */
    void uECC_point_add_wp(uint8_t X1[uECC_BYTES], uint8_t Y1[uECC_BYTES], uint8_t X2[uECC_BYTES], uint8_t Y2[uECC_BYTES]);


    int uECC_compute_public_key_wp(const uint8_t private_key[uECC_BYTES],
        uint8_t public_key[uECC_BYTES * 2]);

    int uECC_shared_secret_wp(const uint8_t public_key[uECC_BYTES * 2],
        const uint8_t private_key[uECC_BYTES],
        uint8_t secret[uECC_BYTES * 2]);

    void uECC_n_operation_wp(uint8_t result[uECC_BYTES], uint8_t HASH[uECC_BYTES], uint8_t A[uECC_BYTES], uint8_t B[uECC_BYTES]);



#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _MICRO_ECC_H_ */
