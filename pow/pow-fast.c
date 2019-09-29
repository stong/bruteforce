
#include <stdio.h>
#include <endian.h>
#include <stdint.h>

// Retrieve cached sha256 starting with XXXXXX
int main(int argc, char** argv){ 
    uint32_t key;
    sscanf(argv[1], "%x", &key);
    key = ((uint32_t)htonl(key))>>8;
    // printf("%x\n", key);

    uint64_t value;
    FILE* cache = fopen("powcache.bin", "rb");
    fseek(cache, sizeof(uint64_t)*key, SEEK_SET);
    fread(&value, sizeof(uint64_t),1, cache);
    fclose(cache);

    printf("%lu", value);
}