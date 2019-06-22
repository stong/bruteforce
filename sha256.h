#pragma once

#include <intrin.h>

class SHA256H
{
protected:
    // Message block
    static const size_t MBYTES = 64;
    unsigned char msgbuf[MBYTES];
    size_t msgbuf_count;            // length (in byte) of the data currently in the message block
    unsigned __int64 total_count;   // total length (in byte) of the message

    // Intermediate hash
    __m128i h0145;  // h0:h1:h4:h5
    __m128i h2367;  // h2:h3:h6:h7

public:
    SHA256H() { Initialize(); }
    ~SHA256H() {}

    void Update(const void* buf, size_t length);
    void Final(void* digest);

protected:
    void Initialize();
    void ProcessMsgBlock(const unsigned char* msg);
};