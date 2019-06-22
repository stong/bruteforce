// clang -Wall -O3 -mssse3 -msha sha.c -o sha

#include <stdint.h>
#include <immintrin.h>
#include <memory.h>

#define MBYTES 64

typedef struct {
    unsigned char msgbuf[MBYTES];
    size_t msgbuf_count;
    uint64_t total_count;
 
    // Intermediate hash
    __m128i h0123;  // h0 : h1 : h2 : h3
    __m128i h4;     // h4 : 0 : 0 : 0
} sha1_ctx;


#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

void SHA1Init(sha1_ctx* ctx)
{
    ctx->h0123 = _mm_set_epi32(H0, H1, H2, H3);
    ctx->h4    = _mm_set_epi32(H4, 0, 0, 0);
    ctx->msgbuf_count = 0;
    ctx->total_count = 0;
}

void SHA1ProcessMsgBlock(sha1_ctx* ctx, const unsigned char* msg)
{
    // Cyclic W array
    // We keep the W array content cyclically in 4 variables
    // Initially:
    // cw0 = w0 : w1 : w2 : w3
    // cw1 = w4 : w5 : w6 : w7
    // cw2 = w8 : w9 : w10 : w11
    // cw3 = w12 : w13 : w14 : w15
    const __m128i byteswapindex = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    const __m128i* msgx = (const __m128i*)msg;
    __m128i cw0 = _mm_shuffle_epi8(_mm_loadu_si128(msgx), byteswapindex);
    __m128i cw1 = _mm_shuffle_epi8(_mm_loadu_si128(msgx + 1), byteswapindex);
    __m128i cw2 = _mm_shuffle_epi8(_mm_loadu_si128(msgx + 2), byteswapindex);
    __m128i cw3 = _mm_shuffle_epi8(_mm_loadu_si128(msgx + 3), byteswapindex);

// Advance W array cycle
// Inputs: 
//  CW0 = w[t-16] : w[t-15] : w[t-14] : w[t-13]
//  CW1 = w[t-12] : w[t-11] : w[t-10] : w[t-9]
//  CW2 = w[t-8] : w[t-7] : w[t-6] : w[t-5]
//  CW3 = w[t-4] : w[t-3] : w[t-2] : w[t-1]
// Outputs: 
//  CW1 = w[t-12] : w[t-11] : w[t-10] : w[t-9]
//  CW2 = w[t-8] : w[t-7] : w[t-6] : w[t-5]
//  CW3 = w[t-4] : w[t-3] : w[t-2] : w[t-1]
//  CW0 = w[t] : w[t+1] : w[t+2] : w[t+3]
#define CYCLE_W(CW0, CW1, CW2, CW3)         \
    CW0 = _mm_sha1msg1_epu32(CW0, CW1);     \
    CW0 = _mm_xor_si128(CW0, CW2);          \
    CW0 = _mm_sha1msg2_epu32(CW0, CW3); 

    __m128i state1 = ctx->h0123;                     // state1 = a : b : c : d
    __m128i w_next = _mm_add_epi32(cw0, ctx->h4);    // w_next = w0+e : w1 : w2 : w3
    __m128i state2;

    // w0 - w3
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 0);// state2 = a' : b' : c' : d'
    w_next = _mm_sha1nexte_epu32(state1, cw1);  // w_next = w4+e' : w5 : w6 : w7
    // w4 - w7
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 0);
    w_next = _mm_sha1nexte_epu32(state2, cw2);
    // w8 - w11
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 0);
    w_next = _mm_sha1nexte_epu32(state1, cw3);
    // w12 - w15
    CYCLE_W(cw0, cw1, cw2, cw3);    // cw0 = w16 : w17 : w18 : w19
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 0);
    w_next = _mm_sha1nexte_epu32(state2, cw0);
    // w16 - w19
    CYCLE_W(cw1, cw2, cw3, cw0);    // cw1 = w20 : w21 : w22 : w23
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 0);
    w_next = _mm_sha1nexte_epu32(state1, cw1);
    // w20 - w23
    CYCLE_W(cw2, cw3, cw0, cw1);    // cw2 = w24 : w25 : w26 : w27
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 1);
    w_next = _mm_sha1nexte_epu32(state2, cw2);
    // w24 - w27
    CYCLE_W(cw3, cw0, cw1, cw2);    // cw3 = w28 : w29 : w30 : w31
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 1);
    w_next = _mm_sha1nexte_epu32(state1, cw3);
    // w28 - w31
    CYCLE_W(cw0, cw1, cw2, cw3);    // cw0 = w32 : w33 : w34 : w35
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 1);
    w_next = _mm_sha1nexte_epu32(state2, cw0);
    // w32 - w35
    CYCLE_W(cw1, cw2, cw3, cw0);    // cw1 = w36 : w37 : w38 : w39
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 1);
    w_next = _mm_sha1nexte_epu32(state1, cw1);
    // w36 - w39
    CYCLE_W(cw2, cw3, cw0, cw1);    // cw2 = w40 : w41 : w42 : w43
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 1);
    w_next = _mm_sha1nexte_epu32(state2, cw2);
    // w40 - w43
    CYCLE_W(cw3, cw0, cw1, cw2);    // cw3 = w44 : w45 : w46 : w47
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 2);
    w_next = _mm_sha1nexte_epu32(state1, cw3);
    // w44 - w47
    CYCLE_W(cw0, cw1, cw2, cw3);    // cw0 = w48 : w49 : w50 : w51
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 2);
    w_next = _mm_sha1nexte_epu32(state2, cw0);
    // w48 - w51
    CYCLE_W(cw1, cw2, cw3, cw0);    // cw1 = w52 : w53 : w54 : w55
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 2);
    w_next = _mm_sha1nexte_epu32(state1, cw1);
    // w52 - w55
    CYCLE_W(cw2, cw3, cw0, cw1);    // cw2 = w56 : w57 : w58 : w59
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 2);
    w_next = _mm_sha1nexte_epu32(state2, cw2);
    // w56 - w59
    CYCLE_W(cw3, cw0, cw1, cw2);    // cw3 = w60 : w61 : w62 : w63
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 2);
    w_next = _mm_sha1nexte_epu32(state1, cw3);
    // w60 - w63
    CYCLE_W(cw0, cw1, cw2, cw3);    // cw0 = w64 : w65 : w66 : w67
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 3);
    w_next = _mm_sha1nexte_epu32(state2, cw0);
    // w64 - w67
    CYCLE_W(cw1, cw2, cw3, cw0);    // cw1 = w68 : w69 : w70 : w71
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 3);
    w_next = _mm_sha1nexte_epu32(state1, cw1);
    // w68 - w71
    CYCLE_W(cw2, cw3, cw0, cw1);    // cw2 = w72 : w73 : w74 : w75
    state1 = _mm_sha1rnds4_epu32(state2, w_next, 3);
    w_next = _mm_sha1nexte_epu32(state2, cw2);
    // w72 - w75
    CYCLE_W(cw3, cw0, cw1, cw2);    // cw3 = w76 : w77 : w78 : w79
    state2 = _mm_sha1rnds4_epu32(state1, w_next, 3);
    w_next = _mm_sha1nexte_epu32(state1, cw3);

    // w76 - w79
    state1     = _mm_sha1rnds4_epu32(state2, w_next, 3);    // state1 = final a : b : c : d
    ctx->h4    = _mm_sha1nexte_epu32(state2, ctx->h4);      // Add final e to h4
    ctx->h0123 = _mm_add_epi32(state1, ctx->h0123);         // Add final a:b:c:d to h0:h1:h2:h3
}

void SHA1Update(sha1_ctx* ctx, const void* buf, size_t length)
{
    const unsigned char* p = (const unsigned char*)buf;
    ctx->total_count += length;

    // If any bytes are left in the message buffer, 
    // fullfill the block first
    if (ctx->msgbuf_count) {
        size_t c = MBYTES - ctx->msgbuf_count;
        if (length < c) {
            memcpy(ctx->msgbuf + ctx->msgbuf_count, p, length);
            ctx->msgbuf_count += length;
            return;
        }
        else {
            memcpy(ctx->msgbuf + ctx->msgbuf_count, p, c);
            p += c;
            length -= c;
            SHA1ProcessMsgBlock(ctx, ctx->msgbuf);
            ctx->msgbuf_count = 0;
        }
    }

    // When we reach here, we have no data left in the message buffer
    while (length >= MBYTES) {
        // No need to copy into the internal message block
        SHA1ProcessMsgBlock(ctx, p);
        p += MBYTES;
        length -= MBYTES;
    }

    // Leave the remaining bytes in the message buffer
    if (length) {
        memcpy(ctx->msgbuf, p, length);
        ctx->msgbuf_count = length;
    }
}

void SHA1Final(sha1_ctx* ctx, void* digest)
{
    // When we reach here, the block is supposed to be unfullfilled.
    // Add the terminating bit
    ctx->msgbuf[ctx->msgbuf_count++] = 0x80;

    // Need to set total length in the last 8-byte of the block.
    // If there is no room for the length, process this block first
    if (ctx->msgbuf_count + 8 > MBYTES) {
        // Fill zeros and process
        memset(ctx->msgbuf + ctx->msgbuf_count, 0, MBYTES - ctx->msgbuf_count);
        SHA1ProcessMsgBlock(ctx, ctx->msgbuf);
        ctx->msgbuf_count = 0;
    }

    // Fill zeros before the last 8-byte of the block
    memset(ctx->msgbuf + ctx->msgbuf_count, 0, MBYTES - 8 - ctx->msgbuf_count);

    // Set the length of the message in big-endian
    __m128i tmp = _mm_loadl_epi64((__m128i*)&ctx->total_count);
    tmp = _mm_slli_epi64(tmp, 3);   // convert # of bytes to # of bits
    const __m128i total_count_byteswapindex = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7);
    tmp = _mm_shuffle_epi8(tmp, total_count_byteswapindex); // convert to big endian
    _mm_storel_epi64((__m128i*)(ctx->msgbuf + MBYTES - 8), tmp);

    // Process the last block
    SHA1ProcessMsgBlock(ctx, ctx->msgbuf);

    // Set the resulting hash value, upside down
    const __m128i byteswapindex = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i r0123 = _mm_shuffle_epi8(ctx->h0123, byteswapindex);
    __m128i r4    = _mm_shuffle_epi8(ctx->h4, byteswapindex);

    uint32_t* digestdw = (uint32_t*)digest;
    _mm_storeu_si128((__m128i*)digestdw, r0123);
    digestdw[4] = _mm_cvtsi128_si32(r4);
}

#if 0
#include <stdio.h>
int main()
{
    sha1_ctx ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, "a", 1);
    uint8_t digest[20];
    SHA1Final(&ctx, digest);
    for (int i = 0; i < 20; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
#endif