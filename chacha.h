#pragma once

/*
    Original Version from https://github.com/Ginurx/chacha20-c @Ginurx
    Modified by MochaByte to be a Header Only implementation
*/

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* ===== Context ===== */
    struct chacha20_context {
        uint32_t keystream32[16];
        size_t   position;

        uint8_t  key[32];
        uint8_t  nonce[12];
        uint64_t counter;

        uint32_t state[16];
    };

    /* ===== Internal helpers (header-only: static inline) ===== */

    static inline uint32_t chacha20_rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t chacha20_pack4(const uint8_t* a) {

        uint32_t r = 0;
        r |= (uint32_t)a[0] << (0 * 8);
        r |= (uint32_t)a[1] << (1 * 8);
        r |= (uint32_t)a[2] << (2 * 8);
        r |= (uint32_t)a[3] << (3 * 8);
        return r;
    }

    static inline void chacha20_init_block(struct chacha20_context* ctx,
        const uint8_t key[32],
        const uint8_t nonce[12])
    {
        memcpy(ctx->key, key, sizeof(ctx->key));
        memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));


        static const uint8_t sigma[16] = {
            'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
        };

        ctx->state[0] = chacha20_pack4(sigma + 0 * 4);
        ctx->state[1] = chacha20_pack4(sigma + 1 * 4);
        ctx->state[2] = chacha20_pack4(sigma + 2 * 4);
        ctx->state[3] = chacha20_pack4(sigma + 3 * 4);

        ctx->state[4] = chacha20_pack4(key + 0 * 4);
        ctx->state[5] = chacha20_pack4(key + 1 * 4);
        ctx->state[6] = chacha20_pack4(key + 2 * 4);
        ctx->state[7] = chacha20_pack4(key + 3 * 4);
        ctx->state[8] = chacha20_pack4(key + 4 * 4);
        ctx->state[9] = chacha20_pack4(key + 5 * 4);
        ctx->state[10] = chacha20_pack4(key + 6 * 4);
        ctx->state[11] = chacha20_pack4(key + 7 * 4);

        ctx->state[12] = 0;

        ctx->state[13] = chacha20_pack4(nonce + 0 * 4);
        ctx->state[14] = chacha20_pack4(nonce + 1 * 4);
        ctx->state[15] = chacha20_pack4(nonce + 2 * 4);
    }

    static inline void chacha20_block_set_counter(struct chacha20_context* ctx,
        uint64_t counter)
    {
        ctx->state[12] = (uint32_t)counter;
        ctx->state[13] = chacha20_pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
    }

    static inline void chacha20_block_next(struct chacha20_context* ctx) {

        for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d)        \
    x[a] += x[b]; x[d] = chacha20_rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = chacha20_rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = chacha20_rotl32(x[d] ^ x[a],  8); \
    x[c] += x[d]; x[b] = chacha20_rotl32(x[b] ^ x[c],  7);

        for (int i = 0; i < 10; i++) {
            CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
                CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
                CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
                CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
                CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
                CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
                CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
                CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

        uint32_t* counter = ctx->state + 12;
        counter[0]++;                 
        if (counter[0] == 0) {
            counter[1]++;             
            assert(counter[1] != 0);  
        }
    }

    /* ===== Public API ===== */

    static inline void chacha20_init_context(struct chacha20_context* ctx,
        const uint8_t key[32],
        const uint8_t nonce[12],
        uint64_t counter)
    {
        memset(ctx, 0, sizeof(*ctx));
        chacha20_init_block(ctx, key, nonce);
        chacha20_block_set_counter(ctx, counter);

        ctx->counter = counter;
        ctx->position = 64;
    }

    static inline void chacha20_xor(struct chacha20_context* ctx,
        uint8_t* bytes, size_t n_bytes)
    {
        uint8_t* ks8 = (uint8_t*)ctx->keystream32;

        for (size_t i = 0; i < n_bytes; i++) {
            if (ctx->position >= 64) {
                chacha20_block_next(ctx);
                ctx->position = 0;
            }
            bytes[i] ^= ks8[ctx->position++];
        }
    }

#ifdef __cplusplus
}
#endif
