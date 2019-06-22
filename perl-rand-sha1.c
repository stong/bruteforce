// clang -Wall -O3 -mssse3 -msha cpu-brute.c sha.c -o brute

// Failed attempt to brute ida 7.2 installation key :(

// Bullshit ripped from perl source code
#include <stdint.h>
#include <math.h>
#define FREEBSD_DRAND48_SEED_0   (0x330e)


#define FREEBSD_DRAND48_SEED_1   (0xabcd)
#define FREEBSD_DRAND48_SEED_2   (0x1234)
#define FREEBSD_DRAND48_MULT_0   (0xe66d)
#define FREEBSD_DRAND48_MULT_1   (0xdeec)
#define FREEBSD_DRAND48_MULT_2   (0x0005)
#define FREEBSD_DRAND48_ADD      (0x000b)

const unsigned short _rand48_mult[3] = {
                FREEBSD_DRAND48_MULT_0,
                FREEBSD_DRAND48_MULT_1,
                FREEBSD_DRAND48_MULT_2
};

const unsigned short _rand48_add = FREEBSD_DRAND48_ADD;

#define U16 uint16_t
#define U32 uint32_t
typedef struct {
    U16 seed[3];
} perl_drand48_t;

void Perl_drand48_init_r(perl_drand48_t *random_state, U32 seed)
{
    random_state->seed[0] = FREEBSD_DRAND48_SEED_0;
    random_state->seed[1] = (U16) seed;
    random_state->seed[2] = (U16) (seed >> 16);
}


double Perl_drand48_r(perl_drand48_t *random_state)
{
    U32 accu;
    U16 temp[2];

    accu = (U32) _rand48_mult[0] * (U32) random_state->seed[0]
         + (U32) _rand48_add;
    temp[0] = (U16) accu;        /* lower 16 bits */
    accu >>= sizeof(U16) * 8;
    accu += (U32) _rand48_mult[0] * (U32) random_state->seed[1]
          + (U32) _rand48_mult[1] * (U32) random_state->seed[0];
    temp[1] = (U16) accu;        /* middle 16 bits */
    accu >>= sizeof(U16) * 8;
    accu += _rand48_mult[0] * random_state->seed[2]
          + _rand48_mult[1] * random_state->seed[1]
          + _rand48_mult[2] * random_state->seed[0];
    random_state->seed[0] = temp[0];
    random_state->seed[1] = temp[1];
    random_state->seed[2] = (U16) accu;

    return ldexp((double) random_state->seed[0], -48) +
           ldexp((double) random_state->seed[1], -32) +
           ldexp((double) random_state->seed[2], -16);
}

#include "sha1.h"

#include <stdio.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#define PARALLEL 48
int main()
{
    char* charset = "abcdefghijkmpqrstuvwxyzABCDEFGHJKLMPQRSTUVWXYZ23456789";
    uint8_t hash[20] = {
        0xF2, 0x9F, 0x55, 0xF0, 0x7C, 0x04, 0x3A, 0xD3, 0x4B, 0x3D, 0xE1, 0x50,
        0x50, 0x15, 0x35, 0xF4, 0x44, 0x24, 0xED, 0xAD
    };

    uint8_t pw[37] = {
        0x50, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x43, 0x68, 0x65, 0x63,
        0x6B, 0x48, 0x61, 0x73, 0x68, 0xC4, 0x16, 0x39, 0x79, 0x28, 0x46, 0xE4,
        0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };
    perl_drand48_t rand_state;
    sha1_ctx ctx;
    uint8_t digest[20];
    
    uint32_t seed = 0;
    uint32_t upto = (uint32_t)(0x100000000L / (uint64_t)PARALLEL);
    int worker = 0;
    for (; worker < PARALLEL; worker++) {
        if (!fork()) {
            printf("Worker %d, bruting %x to %x\n", worker,seed,upto);
            break; // child
        }
        seed = upto;
        upto += (uint64_t)(0x100000000L / (uint64_t)PARALLEL);
    }

    do
    {
        if (!(seed & 0xffffff)) printf("%x\n", seed);
        Perl_drand48_init_r(&rand_state, seed);
        for (int i = 0; i < 12; i++)
        {
            int key = (int)(Perl_drand48_r(&rand_state) * 54.0);
            pw[i+0x19] = charset[key];
        }
        SHA1Init(&ctx);
        SHA1Update(&ctx, pw, sizeof(pw));
        SHA1Final(&ctx, digest);
        
        if (!memcmp(digest, hash, 20))
        {
            printf("CRACKED!!!! %u %s\n", seed, &pw[0x19]);
            int fd = open("sice.txt", O_APPEND | O_RDWR | O_CREAT,0);
            dprintf(fd, "CRACKED!!!! %u %s\n", seed, &pw[0x19]);
            close(fd);
            kill(0, SIGQUIT);
            break;
        }
    } while(++seed != upto);
    printf("Worker %d done\n", worker);
}
