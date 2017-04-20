[![Build Status](https://travis-ci.org/sebastien-riou/masked-bit-sliced-aes-128.svg?branch=master)](https://travis-ci.org/sebastien-riou/masked-bit-sliced-aes-128)
# masked-bit-sliced-AES-128
This demonstrate a masked, bit sliced implementation of AES-128.
* masked: It use boolean masking to thwart DPA, template attacks and other side channel attacks.
* bit sliced: It computes much like a hardware implementation. Depending on CPU register size, it can compute several operations simultaneously.

## Packed bit sliced representation
Bit slice implementations of crypto algorithm often process N blocks at the same time, where N is the number of bits of CPU's registers. This provides great speed if there are a lot of independent blocks to process however this is an overkill when processing a single block (due to the significant latency and memory consumption).

This implementation reduce latency and memory footprint by using a "packed bit slice" representation. This computes "only" N/16 blocks at the same time but maintain the same throughput as the classic representation because the latency is also divided by 16.

## Documentation
A Doxygen config file is in the "doxygen" folder. You can generate doc by invoking "doxygen config" from that directory. It will generate a host of information about the code.
For example the figure below is the call graph of the core function:
![alt tag](sec_aes128_enc_packed_bitslice.png)

## Security level
The security concept is sound so the security level could be rather high however this code is only a demo. As it is, it does not provide any security for many reasons. In particular:
- It is coded in C. Side channel resistance cannot be guaranteed by this concept without resorting to assembly code. It may not leak on a particular CPU with a particular compiler with particular settings but you can take for granted that it does leak big time at least in one combination, if not in most combinations.
- It is just boolean masking, it does not contain any other countermeasure.
- No security evaluation has been done. If you give it a spin please get in touch (email is printed by the test program).

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
The code of main.cpp as been used for this benchmark. The benchmark has been done under Debian Linux running in virtual box with Windows 10 as host system. Debian reported the following CPU type: Intel® Core™ i7-4500U CPU @ 1.80GHz.
The setup and the benchmarking code are obviously not very accurate but gives nevertheless an idea on what can be done.
The code as been compiled by "g++ (Debian 4.7.2-5) 4.7.2" with the options "-Ofast -std=c++11 -DBITSLICE_WIDTH=64". As BITSLICE_WIDTH = 64, each call to sec_aes128_enc_packed_bitslice_wrapper_multi computes 4 blocks.

The following show that the implementation of get_random_bitslice has a great impact on performances:
- RND_IMPL == RND_CNT: 540K blocks/s
- RND_IMPL == RND_CPP:  88K blocks/s
