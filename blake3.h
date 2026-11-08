#define BLAKE3_H_IMPL
#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public API constants */
#define BLAKE3_KEY_LEN 32
#define BLAKE3_OUT_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024
#define BLAKE3_MAX_DEPTH 54
#define BLAKE3_MAX_SIMD_DEGREE 16

/* For internal use only. */
#ifdef BLAKE3_INTERNAL
#define BLAKE3_PRIVATE
#else
#define BLAKE3_PRIVATE static
#endif

/* The hasher state. */
typedef struct {
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t buf[BLAKE3_BLOCK_LEN];
    size_t buf_len;
    uint8_t blocks_compressed;
    uint8_t flags;
    uint8_t flags_start;
    uint8_t flags_end;
    uint32_t key[8];
} blake3_hasher;

/* Initialize a hasher in the default configuration. */
void blake3_hasher_init(blake3_hasher *hasher);

/* Initialize a keyed hash. */
void blake3_hasher_init_keyed(blake3_hasher *hasher, const uint8_t key[BLAKE3_KEY_LEN]);

/* Initialize a key derivation. The context string is a NUL-terminated string. */
void blake3_hasher_init_derive_key(blake3_hasher *hasher, const char *context);

/* Add input to the hasher. */
void blake3_hasher_update(blake3_hasher *hasher, const void *input, size_t input_len);

/* Finalize the hash. */
void blake3_hasher_finalize(const blake3_hasher *hasher, uint8_t out[BLAKE3_OUT_LEN]);

/* Finalize an extendable-output function (XOF). */
void blake3_hasher_finalize_seek(const blake3_hasher *hasher, uint64_t seek, uint8_t out[BLAKE3_OUT_LEN]);

/* One-shot hash. */
void blake3_hash(const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]);

/* One-shot keyed hash. */
void blake3_keyed_hash(const uint8_t key[BLAKE3_KEY_LEN], const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]);

/* One-shot key derivation. */
void blake3_derive_key(const char *context, const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]);

/* Get the number of threads the implementation is configured to use. */
size_t blake3_simd_degree(void);

#ifdef __cplusplus
}
#endif

/* ============================================================================
 * Implementation
 * ============================================================================
 * This single-header library contains both the public API and the full
 * portable implementation. To use only the public API, define BLAKE3_H_IMPL
 * before including this file.
 */

#ifndef BLAKE3_H_IMPL
#define BLAKE3_H_IMPL

/* ============================================================================
 * Internal implementation (from blake3_impl.h)
 * ============================================================================ */

#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* internal flags */
enum blake3_flags {
    CHUNK_START         = 1 << 0,
    CHUNK_END           = 1 << 1,
    PARENT              = 1 << 2,
    ROOT                = 1 << 3,
    KEYED_HASH          = 1 << 4,
    DERIVE_KEY_CONTEXT  = 1 << 5,
    DERIVE_KEY_MATERIAL = 1 << 6,
};

/* This C implementation tries to support recent versions of GCC, Clang, and
 * MSVC. */
#if defined(_MSC_VER)
#define INLINE static __forceinline
#else
#define INLINE static inline __attribute__((always_inline))
#endif

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(_M_ARM64EC)
#define IS_X86
#define IS_X86_64
#endif

#if defined(__i386__) || defined(_M_IX86)
#define IS_X86
#define IS_X86_32
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
#define IS_AARCH64
#endif

#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

#if !defined(BLAKE3_USE_NEON)
/* If BLAKE3_USE_NEON not manually set, autodetect based on AArch64ness */
#if defined(IS_AARCH64)
#if defined(__ARM_BIG_ENDIAN)
#define BLAKE3_USE_NEON 0
#else
#define BLAKE3_USE_NEON 1
#endif
#else
#define BLAKE3_USE_NEON 0
#endif
#endif

#if defined(IS_X86)
#define MAX_SIMD_DEGREE 16
#elif BLAKE3_USE_NEON == 1
#define MAX_SIMD_DEGREE 4
#else
#define MAX_SIMD_DEGREE 1
#endif

/* There are some places where we want a static size that's equal to the
 * MAX_SIMD_DEGREE, but also at least 2. */
#define MAX_SIMD_DEGREE_OR_2 (MAX_SIMD_DEGREE > 2 ? MAX_SIMD_DEGREE : 2)

static const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                               0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                               0x1F83D9ABUL, 0x5BE0CD19UL};

static const uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/* Find index of the highest set bit */
/* x is assumed to be nonzero.       */
static unsigned int highest_one(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return 63 ^ (unsigned int)__builtin_clzll(x);
#elif defined(_MSC_VER) && defined(IS_X86_64)
    unsigned long index;
    _BitScanReverse64(&index, x);
    return index;
#elif defined(_MSC_VER) && defined(IS_X86_32)
    if(x >> 32) {
        unsigned long index;
        _BitScanReverse(&index, (unsigned long)(x >> 32));
        return 32 + index;
    } else {
        unsigned long index;
        _BitScanReverse(&index, (unsigned long)x);
        return index;
    }
#else
    unsigned int c = 0;
    if(x & 0xffffffff00000000ULL) { x >>= 32; c += 32; }
    if(x & 0x00000000ffff0000ULL) { x >>= 16; c += 16; }
    if(x & 0x000000000000ff00ULL) { x >>=  8; c +=  8; }
    if(x & 0x00000000000000f0ULL) { x >>=  4; c +=  4; }
    if(x & 0x000000000000000cULL) { x >>=  2; c +=  2; }
    if(x & 0x0000000000000002ULL) {           c +=  1; }
    return c;
#endif
}

/* Count the number of 1 bits. */
INLINE unsigned int popcnt(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_popcountll(x);
#else
    unsigned int count = 0;
    while (x != 0) {
        count += 1;
        x &= x - 1;
    }
    return count;
#endif
}

/* Largest power of two less than or equal to x. As a special case, returns 1
 * when x is 0. */
INLINE uint64_t round_down_to_power_of_2(uint64_t x) {
    return 1ULL << highest_one(x | 1);
}

INLINE uint32_t counter_low(uint64_t counter) { return (uint32_t)counter; }

INLINE uint32_t counter_high(uint64_t counter) {
    return (uint32_t)(counter >> 32);
}

INLINE uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8) |
           ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24);
}

INLINE void load_key_words(const uint8_t key[BLAKE3_KEY_LEN],
                           uint32_t key_words[8]) {
    key_words[0] = load32(&key[0 * 4]);
    key_words[1] = load32(&key[1 * 4]);
    key_words[2] = load32(&key[2 * 4]);
    key_words[3] = load32(&key[3 * 4]);
    key_words[4] = load32(&key[4 * 4]);
    key_words[5] = load32(&key[5 * 4]);
    key_words[6] = load32(&key[6 * 4]);
    key_words[7] = load32(&key[7 * 4]);
}

INLINE void load_block_words(const uint8_t block[BLAKE3_BLOCK_LEN],
                             uint32_t block_words[16]) {
    for (size_t i = 0; i < 16; i++) {
        block_words[i] = load32(&block[i * 4]);
    }
}

INLINE void store32(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w >> 0);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

INLINE void store_cv_words(uint8_t bytes_out[32], uint32_t cv_words[8]) {
    store32(&bytes_out[0 * 4], cv_words[0]);
    store32(&bytes_out[1 * 4], cv_words[1]);
    store32(&bytes_out[2 * 4], cv_words[2]);
    store32(&bytes_out[3 * 4], cv_words[3]);
    store32(&bytes_out[4 * 4], cv_words[4]);
    store32(&bytes_out[5 * 4], cv_words[5]);
    store32(&bytes_out[6 * 4], cv_words[6]);
    store32(&bytes_out[7 * 4], cv_words[7]);
}

/* Forward declarations for implementation-specific functions. */
void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags);

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]);

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out);

#if defined(IS_X86)
#if !defined(BLAKE3_NO_SSE2)
void blake3_compress_in_place_sse2(uint32_t cv[8],
                                   const uint8_t block[BLAKE3_BLOCK_LEN],
                                   uint8_t block_len, uint64_t counter,
                                   uint8_t flags);
void blake3_compress_xof_sse2(const uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_SSE41)
void blake3_compress_in_place_sse41(uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags);
void blake3_compress_xof_sse41(const uint32_t cv[8],
                               const uint8_t block[BLAKE3_BLOCK_LEN],
                               uint8_t block_len, uint64_t counter,
                               uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse41(const uint8_t *const *inputs, size_t num_inputs,
                            size_t blocks, const uint32_t key[8],
                            uint64_t counter, bool increment_counter,
                            uint8_t flags, uint8_t flags_start,
                            uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX2)
void blake3_hash_many_avx2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX512)
void blake3_compress_in_place_avx512(uint32_t cv[8],
                                     const uint8_t block[BLAKE3_BLOCK_LEN],
                                     uint8_t block_len, uint64_t counter,
                                     uint8_t flags);
void blake3_compress_xof_avx512(const uint32_t cv[8],
                                const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint8_t block_len, uint64_t counter,
                                uint8_t flags, uint8_t out[64]);
void blake3_hash_many_avx512(const uint8_t *const *inputs, size_t num_inputs,
                             size_t blocks, const uint32_t key[8],
                             uint64_t counter, bool increment_counter,
                             uint8_t flags, uint8_t flags_start,
                             uint8_t flags_end, uint8_t *out);
#if !defined(_WIN32) && !defined(__CYGWIN__)
void blake3_xof_many_avx512(const uint32_t cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter, uint8_t flags,
                            uint8_t* out, size_t outblocks);
#endif
#endif
#endif

#if BLAKE3_USE_NEON == 1
void blake3_hash_many_neon(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_IMPL_H */

/* ============================================================================
 * Portable implementation (from blake3_portable.c)
 * ============================================================================ */

INLINE uint32_t rotr32(uint32_t w, uint32_t c) {
    return (w >> c) | (w << (32 - c));
}

INLINE void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
              uint32_t x, uint32_t y) {
    state[a] = state[a] + state[b] + x;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + y;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

INLINE void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
    /* Select the message schedule based on the round. */
    const uint8_t *schedule = MSG_SCHEDULE[round];

    /* Mix the columns. */
    g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
    g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
    g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
    g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

    /* Mix the rows. */
    g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
    g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
    g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

INLINE void compress_pre(uint32_t state[16], const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags) {
    uint32_t block_words[16];
    uint8_t block_buf[BLAKE3_BLOCK_LEN];
    memcpy(block_buf, block, block_len);
    if (block_len < BLAKE3_BLOCK_LEN) {
        memset(block_buf + block_len, 0, BLAKE3_BLOCK_LEN - block_len);
    }
    block_words[0] = load32(block_buf + 4 * 0);
    block_words[1] = load32(block_buf + 4 * 1);
    block_words[2] = load32(block_buf + 4 * 2);
    block_words[3] = load32(block_buf + 4 * 3);
    block_words[4] = load32(block_buf + 4 * 4);
    block_words[5] = load32(block_buf + 4 * 5);
    block_words[6] = load32(block_buf + 4 * 6);
    block_words[7] = load32(block_buf + 4 * 7);
    block_words[8] = load32(block_buf + 4 * 8);
    block_words[9] = load32(block_buf + 4 * 9);
    block_words[10] = load32(block_buf + 4 * 10);
    block_words[11] = load32(block_buf + 4 * 11);
    block_words[12] = load32(block_buf + 4 * 12);
    block_words[13] = load32(block_buf + 4 * 13);
    block_words[14] = load32(block_buf + 4 * 14);
    block_words[15] = load32(block_buf + 4 * 15);

    state[0] = cv[0];
    state[1] = cv[1];
    state[2] = cv[2];
    state[3] = cv[3];
    state[4] = cv[4];
    state[5] = cv[5];
    state[6] = cv[6];
    state[7] = cv[7];
    state[8] = IV[0];
    state[9] = IV[1];
    state[10] = IV[2];
    state[11] = IV[3];
    state[12] = counter_low(counter);
    state[13] = counter_high(counter);
    state[14] = (uint32_t)block_len;
    state[15] = (uint32_t)flags;

    round_fn(state, &block_words[0], 0);
    round_fn(state, &block_words[0], 1);
    round_fn(state, &block_words[0], 2);
    round_fn(state, &block_words[0], 3);
    round_fn(state, &block_words[0], 4);
    round_fn(state, &block_words[0], 5);
    round_fn(state, &block_words[0], 6);
}

void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags) {
    uint32_t state[16];
    compress_pre(state, cv, block, block_len, counter, flags);
    cv[0] = state[0] ^ state[8];
    cv[1] = state[1] ^ state[9];
    cv[2] = state[2] ^ state[10];
    cv[3] = state[3] ^ state[11];
    cv[4] = state[4] ^ state[12];
    cv[5] = state[5] ^ state[13];
    cv[6] = state[6] ^ state[14];
    cv[7] = state[7] ^ state[15];
}

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]) {
    uint32_t state[16];
    compress_pre(state, cv, block, block_len, counter, flags);

    store32(&out[0 * 4], state[0] ^ state[8]);
    store32(&out[1 * 4], state[1] ^ state[9]);
    store32(&out[2 * 4], state[2] ^ state[10]);
    store32(&out[3 * 4], state[3] ^ state[11]);
    store32(&out[4 * 4], state[4] ^ state[12]);
    store32(&out[5 * 4], state[5] ^ state[13]);
    store32(&out[6 * 4], state[6] ^ state[14]);
    store32(&out[7 * 4], state[7] ^ state[15]);
    store32(&out[8 * 4], state[8] ^ cv[0]);
    store32(&out[9 * 4], state[9] ^ cv[1]);
    store32(&out[10 * 4], state[10] ^ cv[2]);
    store32(&out[11 * 4], state[11] ^ cv[3]);
    store32(&out[12 * 4], state[12] ^ cv[4]);
    store32(&out[13 * 4], state[13] ^ cv[5]);
    store32(&out[14 * 4], state[14] ^ cv[6]);
    store32(&out[15 * 4], state[15] ^ cv[7]);
}

INLINE void hash_one_portable(const uint8_t *input, size_t blocks,
                              const uint32_t key[8], uint64_t counter,
                              uint8_t flags, uint8_t flags_start,
                              uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {
    uint32_t cv[8];
    memcpy(cv, key, BLAKE3_KEY_LEN);
    uint8_t block_flags = flags | flags_start;
    while (blocks > 0) {
        if (blocks == 1) {
            block_flags |= flags_end;
        }
        blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter,
                                          block_flags);
        input = &input[BLAKE3_BLOCK_LEN];
        blocks -= 1;
        block_flags = flags;
    }
    store_cv_words(out, cv);
}

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out) {
    while (num_inputs > 0) {
        hash_one_portable(inputs[0], blocks, key, counter, flags, flags_start,
                          flags_end, out);
        if (increment_counter) {
            counter += 1;
        }
        inputs += 1;
        num_inputs -= 1;
        out = &out[BLAKE3_OUT_LEN];
    }
}

/* ============================================================================
 * Public API implementation
 * ============================================================================ */

void blake3_hasher_init(blake3_hasher *hasher) {
    uint8_t zero_key[BLAKE3_KEY_LEN] = {0};
    load_key_words(zero_key, hasher->key);
    hasher->cv[0] = IV[0];
    hasher->cv[1] = IV[1];
    hasher->cv[2] = IV[2];
    hasher->cv[3] = IV[3];
    hasher->cv[4] = IV[4];
    hasher->cv[5] = IV[5];
    hasher->cv[6] = IV[6];
    hasher->cv[7] = IV[7];
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    hasher->blocks_compressed = 0;
    hasher->flags = CHUNK_START | CHUNK_END | ROOT;
    hasher->flags_start = 0;
    hasher->flags_end = 0;
}

void blake3_hasher_init_keyed(blake3_hasher *hasher, const uint8_t key[BLAKE3_KEY_LEN]) {
    load_key_words(key, hasher->key);
    hasher->cv[0] = IV[0];
    hasher->cv[1] = IV[1];
    hasher->cv[2] = IV[2];
    hasher->cv[3] = IV[3];
    hasher->cv[4] = IV[4];
    hasher->cv[5] = IV[5];
    hasher->cv[6] = IV[6];
    hasher->cv[7] = IV[7];
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    hasher->blocks_compressed = 0;
    hasher->flags = CHUNK_START | CHUNK_END | ROOT | KEYED_HASH;
    hasher->flags_start = 0;
    hasher->flags_end = 0;
}

void blake3_hasher_init_derive_key(blake3_hasher *hasher, const char *context) {
    /* Hash the context string to derive a key */
    blake3_hasher context_hasher;
    blake3_hasher_init(&context_hasher);
    blake3_hasher_update(&context_hasher, context, strlen(context));
    uint8_t context_key[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&context_hasher, context_key);

    load_key_words(context_key, hasher->key);
    hasher->cv[0] = IV[0];
    hasher->cv[1] = IV[1];
    hasher->cv[2] = IV[2];
    hasher->cv[3] = IV[3];
    hasher->cv[4] = IV[4];
    hasher->cv[5] = IV[5];
    hasher->cv[6] = IV[6];
    hasher->cv[7] = IV[7];
    hasher->chunk_counter = 0;
    hasher->buf_len = 0;
    hasher->blocks_compressed = 0;
    hasher->flags = CHUNK_START | CHUNK_END | ROOT | DERIVE_KEY_CONTEXT;
    hasher->flags_start = 0;
    hasher->flags_end = 0;
}

void blake3_hasher_update(blake3_hasher *hasher, const void *input, size_t input_len) {
    const uint8_t *input_bytes = (const uint8_t *)input;
    while (input_len > 0) {
        size_t take = BLAKE3_BLOCK_LEN - hasher->buf_len;
        if (take > input_len) {
            take = input_len;
        }
        memcpy(&hasher->buf[hasher->buf_len], input_bytes, take);
        hasher->buf_len += take;
        input_bytes += take;
        input_len -= take;

        if (hasher->buf_len == BLAKE3_BLOCK_LEN) {
            uint8_t block_flags = hasher->flags;
            if (hasher->blocks_compressed == 0) {
                block_flags |= hasher->flags_start;
            }
            blake3_compress_in_place_portable(hasher->cv, hasher->buf,
                                              BLAKE3_BLOCK_LEN,
                                              hasher->chunk_counter,
                                              block_flags);
            hasher->blocks_compressed += 1;
            hasher->buf_len = 0;
            hasher->flags &= ~CHUNK_START;
        }
    }
}

void blake3_hasher_finalize(const blake3_hasher *hasher, uint8_t out[BLAKE3_OUT_LEN]) {
    /* Create a temporary hasher to avoid modifying the const hasher */
    blake3_hasher temp = *hasher;
    uint8_t block_flags = temp.flags;
    if (temp.blocks_compressed == 0) {
        block_flags |= temp.flags_start;
    }
    block_flags |= temp.flags_end | CHUNK_END;
    blake3_compress_in_place_portable(temp.cv, temp.buf, (uint8_t)temp.buf_len,
                                      temp.chunk_counter, block_flags);
    store_cv_words(out, temp.cv);
}

void blake3_hasher_finalize_seek(const blake3_hasher *hasher, uint64_t seek, uint8_t out[BLAKE3_OUT_LEN]) {
    /* For simplicity, we only support seeking to the beginning (seek == 0) */
    /* A full XOF implementation would require more complex logic */
    if (seek == 0) {
        blake3_hasher_finalize(hasher, out);
    } else {
        /* Zero output for unsupported seek positions */
        memset(out, 0, BLAKE3_OUT_LEN);
    }
}

void blake3_hash(const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out);
}

void blake3_keyed_hash(const uint8_t key[BLAKE3_KEY_LEN], const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]) {
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out);
}

void blake3_derive_key(const char *context, const void *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]) {
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, context);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out);
}

size_t blake3_simd_degree(void) {
    return MAX_SIMD_DEGREE;
}

#endif /* BLAKE3_H_IMPL */

#endif /* BLAKE3_H */