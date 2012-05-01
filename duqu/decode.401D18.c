#include <stdio.h>
#include <stdint.h>

uint8_t data[] = "\x4d\xb3\x7a\xb3\x6c\xb3\x6a\xb3\x72\xb3\x7a\xb3\x4b\xb3\x77\xb3\x6d\xb3\x7a\xb3\x7e\xb3\x7b\xb3\x1f";

int 
main (int argc, char** argv){
  int i = 0; 
  while (data[i] != 0)
    data[i++] ^= 0x1f;
  //printf("%s\n", data);
  uint32_t hash = 0xF748B421;
  for (i = 0; data[i] != 0; ++i){
    hash *= 0xD4C2087;
    hash ^= data[i];
  }
  printf ("0x%X\n", hash);
  return 0;
}
