/*
Copyright 2016 Sebastien Riou

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#define RND_NULL 0
#define RND_CNT  1
#define RND_CPP  2

//Must be one of RND_* constants
#ifndef RND_IMPL
  #define RND_IMPL RND_CPP
#endif

#include "stdio.h"
#include "time.h"
#include <random>

#include "secure_aes_pbs.h"
#include "string.h"
#define TEST_FAIL 0
#define TEST_PASS 1

std::random_device r;
std::default_random_engine e1(r());
std::uniform_int_distribution<bitslice_t> uniform_dist(0, BITSLICE_MAX);
bitslice_t rnd_cnt;

//Dummy implementation of the get_random_bitslice callback
//It should return a fully randomized bitslice_t
bitslice_t get_random_bitslice(void){
    #if RND_IMPL == RND_NULL
      //completely ruins the side channel countermeasure and benchmarks! (but very useful for debug)
      return 0;
    #elif RND_IMPL == RND_CPP
      //ruins the performances
      return uniform_dist(e1);
    #elif RND_IMPL == RND_CNT
      //completely ruins the side channel countermeasure but get benchmarks right assuming this is replaced by a fast hardware (P)RNG
      return rnd_cnt++;
    #else
      #error "invalid value for RND_IMPL"
    #endif
}


static const uint8_t key0[]      = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t in0[]       = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
static const uint8_t expected0[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
static const uint8_t key1[]      = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t in1[]       = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const uint8_t expected1[] = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A};

void print_block(const uint8_t block[16]){
  unsigned int i;
  for(i=0;i<16;i++){
    printf("%02X ",block[i]);
  }
  printf("\n");
}

int basic_test(void){
    uint8_t out0[16];
  	sec_aes128_enc_packed_bitslice_wrapper(out0,in0,key0);
    print_block(out0);
    if(0!=memcmp(out0,expected0,16))
			return TEST_FAIL;
    uint32_t i, block;
    uint8_t outs[PARALLEL_OPS][16];
    uint8_t keys[PARALLEL_OPS][16];
    for(block=0;block<PARALLEL_OPS;block++){
      memcpy(outs[block],in0,16);
      memcpy(keys[block],key0,16);
    }
    sec_aes128_enc_packed_bitslice_wrapper_multi(outs,outs,keys,PARALLEL_OPS);
    //sanity check
    for(block=0;block<PARALLEL_OPS;block++){
      if(memcmp(out0,outs[block],16)){
        printf("sec_aes128_enc_packed_bitslice_wrapper_multi error: results are not consistent with sec_aes128_enc_packed_bitslice_wrapper.\n");
        for(i=0;i<PARALLEL_OPS;i++) print_block(outs[i]);
        return TEST_FAIL;
      }
    }
    return TEST_PASS;
}

/** Computes AES-128 encryption many time over.
 *  The output of one block becomes the input of the next.
 *  This can be used for benchmark as well as enforcing some work factor.
 */
void loop_encryption(
    uint8_t out[16],        /**< destination for final ciphertext */
    const uint8_t in[16],   /**< plaintext */
    const uint8_t key[16],  /**< key */
    uint32_t iterations     /**< number of iteration to perform */
  ){
      uint32_t i, block;
      uint8_t outs[PARALLEL_OPS][16];
      uint8_t keys[PARALLEL_OPS][16];
      for(block=0;block<PARALLEL_OPS;block++){
        memcpy(outs[block],in,16);
        memcpy(keys[block],key,16);
      }
      for(i=0;i<iterations;i++){
        sec_aes128_enc_packed_bitslice_wrapper_multi(outs,outs,keys,PARALLEL_OPS);
      }
      //sanity check
      for(block=1;block<PARALLEL_OPS;block++){
        if(memcmp(outs[0],outs[block],16)){
          printf("sec_aes128_enc_packed_bitslice_wrapper_multi error: results are not consistent.\n");
          for(i=0;i<PARALLEL_OPS;i++) print_block(outs[i]);
          while(1);
        }
      }
      memcpy(out,outs[0],16);
}

int main(void){
    clock_t start, end;
    uint32_t iterations = 100000;
    uint8_t out[16];
    printf("Contact: %s@%s\n","sriou","nimp.co.uk");
    {
        char * pa[2];
        char * pa1 = (char *)&pa[1];
        char * pa0 = (char *)&pa[0];
        printf("Estimated CPU word size: %d bits\n",(int)((pa1 - pa0)*8));
    }
    rnd_cnt = uniform_dist(e1);
    printf("BITSLICE_WIDTH = %d, PARALLEL_OPS = %d\n",BITSLICE_WIDTH,PARALLEL_OPS);
    printf("RND_IMPL=%d, here are 32 bytes worth of random bitslice_t:\n",RND_IMPL);
    for(unsigned int i=0;i<32*8/BITSLICE_WIDTH;i++){
      bitslice_t r = get_random_bitslice();
      uint8_t* r_bytes = (uint8_t*)&r;
      for(unsigned int b=0;b<BITSLICE_WIDTH/8;b++) printf("%02X ",r_bytes[b]);
      printf("\n");
    }
    if(TEST_PASS==basic_test()){
      printf("Basic Test PASS\n");
    } else {
      printf("Basic Test FAIL\n");
    }
    printf("Run loop_encryption with iterations = %d\n",iterations);
    start = clock();
    loop_encryption(out,in0,key0,iterations);
    end = clock();
    double seconds = (end-start)/(double)CLOCKS_PER_SEC;
    double blocks_per_sec = ((double)iterations) * PARALLEL_OPS / seconds;
    printf("loop_encryption done in %f seconds --> %.0f blocks/s\n", seconds,blocks_per_sec);
    print_block(out);
    return 0;
}
