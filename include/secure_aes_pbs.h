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
/*! \file secure_aes_pbs.h
    \brief Masked bit sliced implementation of AES-128 encryption.
    This is only a proof of concept, do not rely on this!
*/
#ifndef __SECURE_AES_PBS_H__
#define __SECURE_AES_PBS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "bitslice.h"

#ifndef PARALLEL_OPS
	//default: optimize for throughput
	#define PARALLEL_OPS (BITSLICE_WIDTH / 16)
#endif

#if BITSLICE_WIDTH < (PARALLEL_OPS * 16)
	#error "BITSLICE_WIDTH < (PARALLEL_OPS * 16)"
#endif

/** Computes AES-128 encryption.
 *  Use standard representation for all parameters.
 *  Supports out = in
 */
void sec_aes128_enc_packed_bitslice_wrapper(
          uint8_t out[16],  /**< destination for ciphertext */
    const uint8_t in[16],   /**< plaintext */
    const uint8_t key[16]   /**< key */
  );

/** Computes several AES-128 encryption in parallel
 *  Use standard representation for all parameters.
 *  Supports out = in
 */
void sec_aes128_enc_packed_bitslice_wrapper_multi(
		uint8_t out[PARALLEL_OPS][16],	/**< destination for ciphertexts */
		uint8_t in [PARALLEL_OPS][16],	/**< plaintexts */
		uint8_t key[PARALLEL_OPS][16],	/**< keys */
		unsigned int n_blocks						/**< number of blocks to process. Must be <= PARALLEL_OPS */
	);

/** Computes AES-128 encryption.
 *  Use masked bitsliced representation for all parameters.
 *  Supports out = in
 */
void sec_aes128_enc_packed_bitslice(
    bitslice_t out[2][8], /**< destination for ciphertext */
    bitslice_t in[2][8],  /**< plaintext */
    bitslice_t key[2][8]  /**< key */
  );

	#ifdef __cplusplus
	}
	#endif

#endif //__SECURE_AES_PBS_H__
