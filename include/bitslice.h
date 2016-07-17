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
#ifndef __BIT_SLICE_H__
#define __BIT_SLICE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"

#define JOIN0(a, b)                     a ## b
#define JOIN(a, b)                      JOIN0(a, b)

//bitslice_t definition
//typically that's the CPU register size.
#ifndef BITSLICE_WIDTH
	#define BITSLICE_WIDTH 32
#endif
typedef JOIN(JOIN(uint,BITSLICE_WIDTH),_t) bitslice_t;

//generate the maximum value of a bitslice (without using any intermediate larger than bitslice_t)
#define BITSLICE_MAX ((bitslice_t)(((((bitslice_t)1)<<(BITSLICE_WIDTH-1))-1) | (((bitslice_t)1)<<(BITSLICE_WIDTH-1))))

void bytes_to_bitslice(bitslice_t *out, const uint8_t *const in, unsigned int bitslice, unsigned int size_in_bytes);
void bitslice_to_bytes(uint8_t *out, const bitslice_t *const in, unsigned int bitslice, unsigned int size_in_bytes);

void xor_bitslice(bitslice_t *out, const bitslice_t *const a, const bitslice_t *const b, unsigned int width);
void xor_byte_cste_bitslice(bitslice_t *out, const bitslice_t *const a, uint8_t cste);
void xor_byte_cste_single_slice(bitslice_t *out, const bitslice_t *const a, uint8_t cste, unsigned int bitslice);

void randomize_bitslice(bitslice_t *in_out, unsigned int width);


void bytes_to_packed_bitslice(bitslice_t *out, const uint8_t *const in, unsigned int size_in_bytes);
/** Insert an array of bytes into an array of bitslices.
 * The destination must have been initialized either to 0 or using bytes_to_packed_bitslice
 */
void insert_bytes_to_packed_bitslice(
		bitslice_t *out, 							/**< pointer to the output bitslices. out[0] to out[7] are written. */
		const uint8_t *const in, 			/**< pointer to the input array of bytes */
		unsigned int size_in_bytes,   /**< number of input bytes. The maximum is sizeof(bitslice_t)*8 */
		unsigned int bitslice_offset	/**< offset in the bitslice to store the lsb of input */
	);
/** Convert an array of bitslices to an array of bytes.
 *
 */
void packed_bitslice_to_bytes(
	 	uint8_t *out, 							/**< pointer to the output array of bytes */
	 	const bitslice_t *const in, /**< pointer to the input bitslices. out[0] to out[7] are read. */
	 	unsigned int size_in_bytes	/**< number of output bytes. The maximum is sizeof(bitslice_t)*8 */
 	);

//should be provided externally:
bitslice_t get_random_bitslice(void);

#ifdef __cplusplus
}
#endif

#endif //__BIT_SLICE_H__
