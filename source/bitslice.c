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
/*! \file bitslice.c
    \brief helper functions to work with bit slice representations.
*/
#include "string.h"
#include "bitslice.h"

/** Fill one or more bitslices with random bits.
 *  The random bits are provided by the <code>get_random_bitslice</code> callback
 */
void randomize_bitslice(
		bitslice_t *out,	 		/**< pointer to the output bitslices */
		unsigned int width		/**< number of bitslices to randomize */
	){
	unsigned int i;
	for(i=0;i<width;i++)
		out[i] = get_random_bitslice();
}

/** Convert an array of bytes to an array of bitslices.
 *
 */
void bytes_to_packed_bitslice(
		bitslice_t *out, 						/**< pointer to the output bitslices. out[0] to out[7] are written. */
		const uint8_t *const in, 		/**< pointer to the input array of bytes */
		unsigned int size_in_bytes	/**< number of input bytes. The maximum is sizeof(bitslice_t)*8 */
	){
	unsigned int b,i;
	for(i=0;i<8;i++){
		out[i]=0;
		for(b=0;b<size_in_bytes;b++){
			bitslice_t bit = (1 & (in[b]>>i));
			bit = bit <<b;
			out[i] |= bit;
		}
	}
}

void insert_bytes_to_packed_bitslice(bitslice_t *out,const uint8_t *const in,unsigned int size_in_bytes,unsigned int bitslice_offset){
	unsigned int b,i;
	for(i=0;i<8;i++){
		for(b=0;b<size_in_bytes;b++){
			bitslice_t bit = (1 & (in[b]>>i));
			bit = bit <<(b+bitslice_offset);
			out[i] |= bit;
		}
	}
}

void packed_bitslice_to_bytes(uint8_t *out,const bitslice_t *const in,unsigned int size_in_bytes){
	unsigned int b,i;
	memset(out,0,size_in_bytes);
	for(b=0;b<size_in_bytes;b++){
		for(i=0;i<8;i++) out[b] |= ((in[i]>>b) & 1)<<i;
	}
}

void bytes_to_bitslice(bitslice_t *out, const uint8_t *const in, unsigned int bitslice, unsigned int size_in_bytes){
	unsigned int b,i;
	for(b=0;b<size_in_bytes;b++){
		for(i=0;i<8;i++) out[b*8+i] = (1 & (in[b]>>i))<<bitslice;
	}
}

void bitslice_to_bytes(uint8_t *out, const bitslice_t *const in, unsigned int bitslice, unsigned int size_in_bytes){
	unsigned int b,i;
	memset(out,0,size_in_bytes);
	for(b=0;b<size_in_bytes;b++){
		for(i=0;i<8;i++) out[b] |= ((in[b*8+i]>>bitslice) & 1)<<i;
	}
}

void xor_bitslice(bitslice_t *out, const bitslice_t *const a, const bitslice_t *const b, unsigned int width){
	unsigned int i;
	for(i=0;i<width;i++)
		out[i] = a[i] ^ b[i];
}

void xor_byte_cste_bitslice(bitslice_t *out, const bitslice_t *const a, uint8_t cste){
	unsigned int i;
	bitslice_t c;
	bitslice_t ones = 0;
	ones--;
	for(i=0;i<8;i++){
		c = cste & (1<<i) ? ones : 0;
		out[i] = a[i] ^ c;
	}
}

void xor_byte_cste_single_slice(bitslice_t *out, const bitslice_t *const a, uint8_t cste, unsigned int bitslice){
	unsigned int i;
	bitslice_t c;
	bitslice_t one = 1<<bitslice;
	for(i=0;i<8;i++){
		c = cste & (1<<i) ? one : 0;
		out[i] = a[i] ^ c;
	}
}

void xor_byte_cste_multi_slice(bitslice_t *out, const bitslice_t *const a, uint8_t cste, bitslice_t bitslice_mask){
	unsigned int i;
	bitslice_t c;
	bitslice_t one = bitslice_mask;
	for(i=0;i<8;i++){
		c = cste & (1<<i) ? one : 0;
		out[i] = a[i] ^ c;
	}
}
