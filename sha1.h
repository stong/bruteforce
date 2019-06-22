#include <immintrin.h>
typedef struct {
#define MBYTES 64
    unsigned char msgbuf[MBYTES];
    size_t msgbuf_count;
    uint64_t total_count;
    __m128i h0123;
    __m128i h4;
} sha1_ctx;
void SHA1Init(sha1_ctx* ctx);
void SHA1Update(sha1_ctx* ctx, const void* buf, size_t length);
void SHA1Final(sha1_ctx* ctx, void* digest);
