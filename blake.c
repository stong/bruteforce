// compile me with -O3
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sodium.h>

#define PARALLEL 7

int main(){
  uint8_t buf[64];
  uint8_t hash[16];
  memset(buf, 0, 64);
  read(0, buf, 16);

  // parallelism shit
  setpgid(0,0);
  unsigned int brute = 0;
  uint64_t upto = (0x100000000L / (uint64_t)PARALLEL);
  int worker = 0;
  for (;worker < PARALLEL; worker++) {
      if (!fork()) {
          fprintf(stderr, "worker %d, %x to %lx\n", worker,brute,upto);
          break; // child
      }
      brute = upto;
      upto += (0x100000000L / (uint64_t)PARALLEL);
  }
  uint32_t start = brute;

  do {
    if ((brute & 0xffffff) == 0) fprintf(stderr, "%08x, %.02f%% done\n", brute, 100.f*(brute-start)/(float)(upto-start));
    *(uint32_t*)(&buf[16]) = brute;

    // check
    crypto_generichash(hash, 16, buf, 64, 0, 0);
    if ((*(uint32_t*)hash & 0x00ffffff) != 0)
      goto fail;

    //gucci
    write(1, buf, 64);
    // int fd = open("sice.txt", O_APPEND | O_RDWR | O_CREAT,0);
    // dprintf(fd, "FOUND IT!!!!!!! %08x\n", brute);
    // close(fd);
    kill(0, SIGQUIT); // kill process group
    break;

    fail:
    brute++;
  } while(brute < upto);
  fprintf(stderr, "exhausted...\n");
}

