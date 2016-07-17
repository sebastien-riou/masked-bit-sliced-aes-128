# masked-bit-sliced-AES-128
This demonstrate a masked, bit sliced implementation of AES-128.
* masked: It use boolean masking to thwart DPA, template attacks and other side channel attacks.
* bit sliced: It computes much like a hardware implementation. Depending on CPU register size, it can compute several operations simultaneously.

## Packed bit sliced representation
Bit slice implementations of crypto algorithm often process N blocks at the same time, where N is the number of bits of CPU's registers. This provides great speed if there are a lot of independent blocks to process however this is an overkill when processing a single block (due to the significant latency and memory consumption).

This implementation reduce latency and memory footprint by using a "packed bit slice" representation. This computes "only" N/16 blocks at the same time but maintain the same throughput as the classic representation because the latency is also divided by 16.

## Security level
The security concept is sound so the security level could be rather high however this code is only a demo. As it is, it does not provide any security for many reasons. In particular:
- It is coded in C. Side channel resistance cannot be guaranteed by this concept without resorting to assembly code. It may not leak on a particular CPU with a particular compiler with particular settings but you can take for granted that it does leak big time at least in one combination, if not in most combinations.
- It is just boolean masking, it does not contain any other countermeasure.
- No security evaluation has been done.

Note the security level depends heavily on the quality of the random numbers provided by the get_random_bitslice callback.

## Performances
The code aims for clarity rather than speed. Plenty of optimizations opportunities have not been exploited so the benchmarks done on this code are giving a higher bound on execution time rather than a realistic estimation of the potential performances of the approach.

### Benchmark on Cortex-M0+
Execution time depends on the definition of bitslice_t, controlled by the constant BITSLICE_WIDTH. For Cortex-M0+ the best choice is BITSLICE_WIDTH = 32.

With a 32 bit bitslice_t, we can compute one or two blocks in parallel. For Cortex-M0+ an optimization is possible if we need to compute a single block because only 16 bit immediate values are needed then. For that reason the code support a build time constant PARALLEL_OPS which can be set to 0 or 1.
- PARALLEL_OPS = 0: best if we are interested in having the lowest latency. We compute a single block at a time as fast as we can.
- PARALLEL_OPS = 1: best if we are interested in throughput. We compute two blocks in parallel for slightly more instructions.

The benchmark has been done on the Keil instruction set simulator, with get_random_bitslice reading 32 bit random numbers from a PRNG peripheral, so this is as fast as it can get.

Note that Keil ISS does not model wait cycles on busses, so it does not provide accurate clock cycles. For that reason the execution time is reported in "states", as provided within Keil's register view "internal".

The code has been compiled with armcc -O3 -Otime.

#### PARALLEL_OPS = 1
- Execution states: 69K
- Code size: 3748 bytes
- Stack usage: 1056 bytes

#### PARALLEL_OPS = 2
- Execution states: 80K
- Code size: 3986 bytes
- Stack usage: 1128 bytes

So that's about 40K "states" per block. For comparison, the wolfssl table based implementation takes 2K "states", so the cost of that countermeasure is a factor 20 in runtime.

## Benchmark on Linux / Intel i7
The code below as been used for this benchmark.
```cpp
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
}```

The benchmark has been done under Debian Linux running in virtual box with Windows 10 as host system. Debian reported the following CPU type: Intel® Core™ i7-4500U CPU @ 1.80GHz.
The setup and the benchmarking code are obviously not very accurate but gives nevertheless an idea on what can be done.
The code as been compiled by "g++ (Debian 4.7.2-5) 4.7.2" with the options "-Ofast -std=c++11 -DBITSLICE_WIDTH=64". As BITSLICE_WIDTH = 64, each call to sec_aes128_enc_packed_bitslice_wrapper_multi computes 4 blocks.

The following show that the implementation of get_random_bitslice has a great impact on performances:
- RND_IMPL == RND_CNT: 540K blocks/s
- RND_IMPL == RND_CPP:  88K blocks/s
