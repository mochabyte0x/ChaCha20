#pragma once

/*
    Original Version from https://github.com/Ginurx/chacha20-c @Ginurx
    Modified by MochaByte to be a Header Only implementation
*/

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) && !defined(CHACHA20_USE_STDINT)
// MSVC: avoid <stdint.h>
    typedef unsigned __int8   c20_u8;
    typedef unsigned __int32  c20_u32;
    typedef unsigned __int64  c20_u64;
#else
// Portable: allow opting into stdint
#include <stdint.h>
    typedef uint8_t  c20_u8;
    typedef uint32_t c20_u32;
    typedef uint64_t c20_u64;
#endif

    typedef c20_u64 c20_size;

    static __inline void c20_memset(void* dst, int v, c20_size n) {
        c20_u8* d = (c20_u8*)dst; c20_u8 b = (c20_u8)v;
        for (c20_size i = 0; i < n; ++i) d[i] = b;
    }
    static __inline void c20_memcpy(void* dst, const void* src, c20_size n) {
        c20_u8* d = (c20_u8*)dst; const c20_u8* s = (const c20_u8*)src;
        for (c20_size i = 0; i < n; ++i) d[i] = s[i];
    }

    /* ---------- context ---------- */
    struct chacha20_context {
        c20_u32 keystream32[16];
        c20_size position;

        c20_u8  key[32];
        c20_u8  nonce[12];
        c20_u64 counter;

        c20_u32 state[16];
    };

    /* ---------- internals ---------- */
    static __inline c20_u32 chacha20_rotl32(c20_u32 x, int n) {
        return (c20_u32)((x << n) | (x >> (32 - n)));
    }

    static __inline c20_u32 chacha20_pack4(const c20_u8* a) {
        return (c20_u32)a[0]
            | ((c20_u32)a[1] << 8)
            | ((c20_u32)a[2] << 16)
            | ((c20_u32)a[3] << 24);
    }

    static __inline void chacha20_init_block(struct chacha20_context* ctx,
        const c20_u8 key[32],
        const c20_u8 nonce[12])
    {
        c20_memcpy(ctx->key, key, 32);
        c20_memcpy(ctx->nonce, nonce, 12);

        static const c20_u8 sigma[16] = {
            'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
        };

        ctx->state[0] = chacha20_pack4(sigma + 0);
        ctx->state[1] = chacha20_pack4(sigma + 4);
        ctx->state[2] = chacha20_pack4(sigma + 8);
        ctx->state[3] = chacha20_pack4(sigma + 12);

        ctx->state[4] = chacha20_pack4(key + 0);
        ctx->state[5] = chacha20_pack4(key + 4);
        ctx->state[6] = chacha20_pack4(key + 8);
        ctx->state[7] = chacha20_pack4(key + 12);
        ctx->state[8] = chacha20_pack4(key + 16);
        ctx->state[9] = chacha20_pack4(key + 20);
        ctx->state[10] = chacha20_pack4(key + 24);
        ctx->state[11] = chacha20_pack4(key + 28);

        ctx->state[12] = 0; 
        ctx->state[13] = chacha20_pack4(nonce + 0);
        ctx->state[14] = chacha20_pack4(nonce + 4);
        ctx->state[15] = chacha20_pack4(nonce + 8);
    }

    static __inline void chacha20_block_set_counter(struct chacha20_context* ctx,
        c20_u64 counter)
    {
        ctx->state[12] = (c20_u32)counter;                   
        ctx->state[13] = chacha20_pack4(ctx->nonce + 0)      
            + (c20_u32)(counter >> 32);          
    }

    static __inline void chacha20_block_next(struct chacha20_context* ctx) {
        for (int i = 0; i < 16; ++i) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QR(x,a,b,c,d)                         \
    x[a] += x[b]; x[d] = chacha20_rotl32(x[d] ^ x[a],16); \
    x[c] += x[d]; x[b] = chacha20_rotl32(x[b] ^ x[c],12); \
    x[a] += x[b]; x[d] = chacha20_rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = chacha20_rotl32(x[b] ^ x[c], 7);

        for (int i = 0; i < 10; ++i) {
            CHACHA20_QR(ctx->keystream32, 0, 4, 8, 12)
                CHACHA20_QR(ctx->keystream32, 1, 5, 9, 13)
                CHACHA20_QR(ctx->keystream32, 2, 6, 10, 14)
                CHACHA20_QR(ctx->keystream32, 3, 7, 11, 15)
                CHACHA20_QR(ctx->keystream32, 0, 5, 10, 15)
                CHACHA20_QR(ctx->keystream32, 1, 6, 11, 12)
                CHACHA20_QR(ctx->keystream32, 2, 7, 8, 13)
                CHACHA20_QR(ctx->keystream32, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; ++i) ctx->keystream32[i] += ctx->state[i];

        c20_u32* ctr = ctx->state + 12;
        ctr[0] += 1U;
        if (ctr[0] == 0U) {
            ctr[1] += 1U; 

        }
    }

    /* ---------- public API ---------- */
    static __inline void chacha20_init_context(struct chacha20_context* ctx,
        const c20_u8 key[32],
        const c20_u8 nonce[12],
        c20_u64 counter)
    {
        c20_memset(ctx, 0, (c20_size)sizeof(*ctx));
        chacha20_init_block(ctx, key, nonce);
        chacha20_block_set_counter(ctx, counter);
        ctx->counter = counter;
        ctx->position = 64; 
    }

    static __inline void chacha20_xor(struct chacha20_context* ctx,
        c20_u8* bytes, c20_size n_bytes)
    {
        c20_u8* ks8 = (c20_u8*)ctx->keystream32;
        for (c20_size i = 0; i < n_bytes; ++i) {
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
