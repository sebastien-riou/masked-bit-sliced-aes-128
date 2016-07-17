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
/*! \file secure_aes_pbs.c
    \brief Masked bit sliced implementation of AES-128 encryption.
    This is only a proof of concept, do not rely on this!
*/
#include "secure_aes_pbs.h"
#include <string.h>

/** Bit slice implementation of aes_sbox.
* formulae from http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
* 113 gates, 27 depth
* This function is there for reference only. It was the first step towards the masked implementation
*/
static void aes_sbox_bitslice_ref(bitslice_t *out, const bitslice_t * const in){
	bitslice_t y14 = in[ 4] ^ in[ 2];
	bitslice_t y13 = in[ 7] ^ in[ 1];
	bitslice_t y9 = in[ 7] ^ in[ 4];
	bitslice_t y8 = in[ 7] ^ in[ 2];
	bitslice_t t0 = in[ 6] ^ in[ 5];
	bitslice_t y1 = t0 ^ in[ 0];
	bitslice_t y4 = y1 ^ in[ 4];
	bitslice_t y12 = y13 ^ y14;
	bitslice_t y2 = y1 ^ in[ 7];
	bitslice_t y5 = y1 ^ in[ 1];
	bitslice_t y3 = y5 ^ y8;
	bitslice_t t1 = in[ 3] ^ y12;
	bitslice_t y15 = t1 ^ in[ 2];
	bitslice_t y20 = t1 ^ in[ 6];
	bitslice_t y6 = y15 ^ in[ 0];
	bitslice_t y10 = y15 ^ t0;
	bitslice_t y11 = y20 ^ y9;
	bitslice_t y7 = in[ 0] ^ y11;
	bitslice_t y17 = y10 ^ y11;
	bitslice_t y19 = y10 ^ y8;
	bitslice_t y16 = t0 ^ y11;
	bitslice_t y21 = y13 ^ y16;
	bitslice_t y18 = in[ 7] ^ y16;
	bitslice_t t2 = y12 & y15;
	bitslice_t t3 = y3 & y6;
	bitslice_t t4 = t3 ^ t2;
	bitslice_t t5 = y4 & in[ 0];
	bitslice_t t6 = t5 ^ t2;
	bitslice_t t7 = y13 & y16;
	bitslice_t t8 = y5 & y1;
	bitslice_t t9 = t8 ^ t7;
	bitslice_t t10 = y2 & y7;
	bitslice_t t11 = t10 ^ t7;
	bitslice_t t12 = y9 & y11;
	bitslice_t t13 = y14 & y17;
	bitslice_t t14 = t13 ^ t12;
	bitslice_t t15 = y8 & y10;
	bitslice_t t16 = t15 ^ t12;
	bitslice_t t17 = t4 ^ y20;
	bitslice_t t18 = t6 ^ t16;
	bitslice_t t19 = t9 ^ t14;
	bitslice_t t20 = t11 ^ t16;
	bitslice_t t21 = t17 ^ t14;
	bitslice_t t22 = t18 ^ y19;
	bitslice_t t23 = t19 ^ y21;
	bitslice_t t24 = t20 ^ y18;
	bitslice_t t25 = t21 ^ t22;
	bitslice_t t26 = t21 & t23;///////////////////////////////////////
	bitslice_t t27 = t24 ^ t26;
	bitslice_t t28 = t25 & t27;///////////////////////////////////////
	bitslice_t t29 = t28 ^ t22;
	bitslice_t t30 = t23 ^ t24;
	bitslice_t t31 = t22 ^ t26;
	bitslice_t t32 = t31 & t30;
	bitslice_t t33 = t32 ^ t24;
	bitslice_t t34 = t23 ^ t33;
	bitslice_t t35 = t27 ^ t33;
	bitslice_t t36 = t24 & t35;
	bitslice_t t37 = t36 ^ t34;
	bitslice_t t38 = t27 ^ t36;
	bitslice_t t39 = t29 & t38;///////////////////////////////////////
	bitslice_t t40 = t25 ^ t39;
	bitslice_t t41 = t40 ^ t37;
	bitslice_t t42 = t29 ^ t33;
	bitslice_t t43 = t29 ^ t40;
	bitslice_t t44 = t33 ^ t37;
	bitslice_t t45 = t42 ^ t41;
	bitslice_t z0 = t44 & y15;///////////////////////////////////////
	bitslice_t z1 = t37 & y6;
	bitslice_t z2 = t33 & in[ 0];
	bitslice_t z3 = t43 & y16;
	bitslice_t z4 = t40 & y1;
	bitslice_t z5 = t29 & y7;
	bitslice_t z6 = t42 & y11;
	bitslice_t z7 = t45 & y17;
	bitslice_t z8 = t41 & y10;
	bitslice_t z9 = t44 & y12;
	bitslice_t z10 = t37 & y3;
	bitslice_t z11 = t33 & y4;
	bitslice_t z12 = t43 & y13;
	bitslice_t z13 = t40 & y5;
	bitslice_t z14 = t29 & y2;
	bitslice_t z15 = t42 & y9;
	bitslice_t z16 = t45 & y14;
	bitslice_t z17 = t41 & y8;
	bitslice_t tc1 = z15 ^ z16;
	bitslice_t tc2 = z10 ^ tc1;
	bitslice_t tc3 = z9 ^ tc2;
	bitslice_t tc4 = z0 ^ z2;
	bitslice_t tc5 = z1 ^ z0;
	bitslice_t tc6 = z3 ^ z4;
	bitslice_t tc7 = z12 ^ tc4;
	bitslice_t tc8 = z7 ^ tc6;
	bitslice_t tc9 = z8 ^ tc7;
	bitslice_t tc10 = tc8 ^ tc9;
	bitslice_t tc11 = tc6 ^ tc5;
	bitslice_t tc12 = z3 ^ z5;
	bitslice_t tc13 = z13 ^ tc1;
	bitslice_t tc14 = tc4 ^ tc12;
	out[ 4] = tc3 ^ tc11;
	{
		bitslice_t tc16 = z6 ^ tc8;
		bitslice_t tc17 = z14 ^ tc10;
		bitslice_t tc18 = tc13 ^ tc14;

		out[ 0] = z12 ^ ~ tc18;
		{
			bitslice_t tc20 = z15 ^ tc16;
			bitslice_t tc21 = tc2 ^ z11;
			out[ 7] = tc3 ^ tc16;
			out[ 1] = tc10 ^ ~ tc18;
			out[ 3] = tc14 ^ out[ 4];
			out[ 6] = out[ 4] ^ ~ tc16;
			{
				bitslice_t tc26 = tc17 ^ tc20;
				out[ 5] = tc26 ^ ~ z17;
				out[ 2] = tc21 ^ tc17;
			}
		}
	}
}

static void aes_sbox_input_map(bitslice_t in_lm[21], const bitslice_t * const in){
	in_lm[0] = in[ 6] ^ in[ 5];
	in_lm[1] = in_lm[0] ^ in[ 0];
	in_lm[2] = in_lm[1] ^ in[ 7];
	in_lm[3] = in[ 4] ^ in[ 2];
	in_lm[4] = in[ 7] ^ in[ 1];
	in_lm[5] = in[ 7] ^ in[ 4];
	in_lm[6] = in[ 7] ^ in[ 2];
	in_lm[7] = in_lm[1] ^ in[ 4];
	in_lm[8] = in_lm[4] ^ in_lm[3];
	in_lm[9] = in_lm[1] ^ in[ 1];
	in_lm[10] = in_lm[9] ^ in_lm[6];
	in_lm[11] = in[ 3] ^ in_lm[8];
	in_lm[12] = in_lm[11] ^ in[ 2];
	in_lm[13] = in_lm[11] ^ in[ 6];
	in_lm[14] = in_lm[12] ^ in[ 0];
	in_lm[15] = in_lm[12] ^ in_lm[0];
	in_lm[16] = in_lm[13] ^ in_lm[5];
	in_lm[17] = in[ 0] ^ in_lm[16];
	in_lm[18] = in_lm[15] ^ in_lm[16];
	in_lm[19] = in_lm[0] ^ in_lm[16];
	in_lm[20] = in_lm[4] ^ in_lm[19];
}
static void aes_sbox_non_linear_map0(bitslice_t nlm0[9], const bitslice_t * const in, const bitslice_t * const in_lm){
	nlm0[0] = in_lm[10] & in_lm[14];
	nlm0[1] = in_lm[4] & in_lm[19];
	nlm0[2] = in_lm[9] & in_lm[1];
	nlm0[3] = in_lm[2] & in_lm[17];
	nlm0[4] = in_lm[5] & in_lm[16];
	nlm0[5] = in_lm[3] & in_lm[18];
	nlm0[6] = in_lm[6] & in_lm[15];
	nlm0[7] = in_lm[7] & in[ 0];
	nlm0[8] = in_lm[8] & in_lm[12];
}
static void aes_sbox_linear_map0(bitslice_t lm0[7], const bitslice_t * const in, const bitslice_t * const in_lm, const bitslice_t * const nlm0){
	lm0[0] = nlm0[5] ^ nlm0[4];
	lm0[1] = nlm0[6] ^ nlm0[4];
	lm0[2] = nlm0[0] ^ nlm0[8] ^ in_lm[13] ^ lm0[0];
	lm0[3] = nlm0[7] ^ nlm0[8] ^ lm0[1] ^ in_lm[15] ^ in_lm[6];
	lm0[4] = nlm0[2] ^ nlm0[1] ^ lm0[0] ^ in_lm[20];
	lm0[5] = nlm0[3] ^ nlm0[1] ^ lm0[1] ^ in[ 7] ^ in_lm[19];
	lm0[6] = lm0[2] ^ lm0[3];
}
static void aes_sbox_non_linear_map1(bitslice_t nlm1[1], const bitslice_t * const lm0){
	nlm1[0] = lm0[2] & lm0[4];
}
static void aes_sbox_linear_map1(bitslice_t lm1[3], const bitslice_t * const lm0, const bitslice_t * const nlm1){
	lm1[0] = lm0[5] ^ nlm1[0];
	lm1[1] = lm0[4] ^ lm0[5];
	lm1[2] = lm0[3] ^ nlm1[0];
}
static void aes_sbox_non_linear_map2(bitslice_t nlm2[2], const bitslice_t * const lm0, const bitslice_t * const lm1){
	nlm2[0] = lm0[6] & lm1[0];
	nlm2[1] = lm1[2] & lm1[1];
}
static void aes_sbox_linear_map2(bitslice_t lm2[3], const bitslice_t * const lm0, const bitslice_t * const lm1, const bitslice_t * const nlm2){
	lm2[0] = nlm2[0] ^ lm0[3];
	lm2[1] = nlm2[1] ^ lm0[5];
	lm2[2] = lm1[0] ^ lm2[1];
}
static void aes_sbox_non_linear_map3(bitslice_t nlm3[1], const bitslice_t * const in, const bitslice_t * const in_lm, const bitslice_t * const lm0, const bitslice_t * const lm2){
	nlm3[0] = lm0[5] & lm2[2];
	nlm3[1] = lm2[1] & in[ 0];
	nlm3[2] = lm2[0] & in_lm[17];
	nlm3[3] = lm2[1] & in_lm[7];
	nlm3[4] = lm2[0] & in_lm[2];
}
static void aes_sbox_linear_map3(bitslice_t lm3[4], const bitslice_t * const lm0, const bitslice_t * const lm1, const bitslice_t * const lm2, const bitslice_t * const nlm3){
	lm3[0] = nlm3[0] ^ lm0[4] ^ lm2[1];
	lm3[1] = lm1[0] ^ nlm3[0];
	lm3[2] = lm2[0] ^ lm2[1];
	lm3[3] = lm2[1] ^ lm3[0];
}
static void aes_sbox_non_linear_map4(bitslice_t nlm4[7], const bitslice_t * const in_lm, const bitslice_t * const lm2, const bitslice_t * const lm3){
	nlm4[0] = lm2[0] & lm3[1];
	nlm4[1] = lm3[0] & in_lm[14];
	nlm4[2] = lm3[3] & in_lm[12];
	nlm4[3] = lm3[2] & in_lm[16];
	nlm4[4] = lm3[3] & in_lm[8];
	nlm4[5] = lm3[0] & in_lm[10];
	nlm4[6] = lm3[2] & in_lm[5];
}
static void aes_sbox_linear_map4(bitslice_t lm4[4], const bitslice_t * const lm0, const bitslice_t * const lm2, const bitslice_t * const lm3, const bitslice_t * const nlm4){
	lm4[0] = lm0[6] ^ nlm4[0];
	lm4[1] = lm4[0] ^ lm3[0];
	lm4[2] = lm2[0] ^ lm4[0];
	lm4[3] = lm3[2] ^ lm4[1];
}
static void aes_sbox_non_linear_map5(bitslice_t nlm5[8], const bitslice_t * const in_lm, const bitslice_t * const lm4){
	nlm5[0] = lm4[2] & in_lm[19];
	nlm5[1] = lm4[0] & in_lm[1];
	nlm5[2] = lm4[3] & in_lm[18];
	nlm5[3] = lm4[1] & in_lm[15];
	nlm5[4] = lm4[2] & in_lm[4];
	nlm5[5] = lm4[1] & in_lm[6];
	nlm5[6] = lm4[0] & in_lm[9];
	nlm5[7] = lm4[3] & in_lm[3];
}
static void aes_sbox_linear_map5(bitslice_t out[8], bitslice_t lm5[12], const bitslice_t * const nlm3, const bitslice_t * const nlm4, const bitslice_t * const nlm5){
	lm5[0] = nlm4[6] ^ nlm5[7];
	lm5[1] = nlm4[5] ^ lm5[0];
	lm5[2] = nlm4[4] ^ lm5[1];
	lm5[3] = nlm4[2] ^ nlm3[1];
	lm5[4] = nlm5[0] ^ nlm5[1];
	lm5[6] = nlm5[2] ^ lm5[4];
	lm5[7] = lm5[6] ^ nlm5[3] ^ nlm5[4] ^ lm5[3];
	lm5[8] = lm5[3] ^ nlm5[0] ^ nlm3[2];
	lm5[9] = nlm4[3] ^ lm5[6];
	lm5[10] = nlm3[4] ^ lm5[7];
	lm5[11] = nlm5[6] ^ lm5[0] ^ lm5[8];
	out[ 0] = nlm5[4] ^ lm5[11];
	out[ 1] = lm5[7] ^ lm5[11];
	out[ 2] = lm5[1] ^ nlm3[3] ^ lm5[10];
	out[ 4] = lm5[2] ^ lm5[4] ^ nlm4[1] ^ nlm4[2];
	out[ 3] = lm5[8] ^ out[ 4];
	out[ 5] = lm5[10] ^ nlm4[6] ^ lm5[9] ^ nlm5[5];
	out[ 6] = out[ 4] ^ lm5[9];
	out[ 7] = lm5[2] ^ lm5[9];
}
static void aes_sbox_output_map(bitslice_t out[8]){
	out[ 0] = ~out[ 0];
	out[ 1] = ~out[ 1];
	out[ 5] = ~out[ 5];
	out[ 6] = ~out[ 6];
}

/** Bit slice implementation of aes_sbox.
* This is the same algorithm as in aes_sbox_bitslice_ref however it is structured to separate the linear and non linear layers.
* This function is there for reference only. It was the second step towards the masked implementation
*/
static void aes_sbox_bitslice(bitslice_t *out, const bitslice_t * const in){
	bitslice_t in_lm[21];
	bitslice_t nlm0[9];
	bitslice_t lm0[7];
	bitslice_t nlm1[1];
	bitslice_t lm1[3];
	bitslice_t nlm2[2];
	bitslice_t lm2[3];
	bitslice_t nlm3[5];
	bitslice_t lm3[4];
	bitslice_t nlm4[7];
	bitslice_t lm4[4];
	bitslice_t nlm5[8];
	bitslice_t lm5[24];
	aes_sbox_input_map(in_lm,in);
	aes_sbox_non_linear_map0(nlm0,in,in_lm);
	aes_sbox_linear_map0(lm0,in,in_lm,nlm0);
	aes_sbox_non_linear_map1(nlm1,lm0);
	aes_sbox_linear_map1(lm1,lm0,nlm1);
	aes_sbox_non_linear_map2(nlm2,lm0,lm1);
	aes_sbox_linear_map2(lm2,lm0,lm1,nlm2);
	aes_sbox_non_linear_map3(nlm3,in,in_lm,lm0,lm2);
	aes_sbox_linear_map3(lm3,lm0,lm1,lm2,nlm3);
	aes_sbox_non_linear_map4(nlm4,in_lm,lm2,lm3);
	aes_sbox_linear_map4(lm4,lm0,lm2,lm3,nlm4);
	aes_sbox_non_linear_map5(nlm5,in_lm,lm4);
	aes_sbox_linear_map5(out,lm5,nlm3,nlm4,nlm5);
	aes_sbox_output_map(out);
}

/** Masked bitwise AND
* This should really be coded in assembly...
*/
static void and_2shares(bitslice_t *out0,bitslice_t *out1, bitslice_t a0, bitslice_t a1, bitslice_t b0, bitslice_t b1){
	bitslice_t n00 = a0 & b0;
	bitslice_t n01 = a0 & b1;
	bitslice_t n10 = a1 & b0;
	bitslice_t n11 = a1 & b1;
	bitslice_t r = get_random_bitslice();
	*out0 = (r^n00)^n11;
	*out1 = (r^n01)^n10;
}

static void aes_sbox_non_linear_map0_2shares(bitslice_t nlm0[2][9], bitslice_t in[2][8], bitslice_t in_lm[2][21]){
	and_2shares(&nlm0[0][0],&nlm0[1][0],in_lm[0][10],in_lm[1][10],in_lm[0][14],in_lm[1][14]);//nlm0[0] = in_lm[10] & in_lm[14];
	and_2shares(&nlm0[0][1],&nlm0[1][1],in_lm[0][ 4],in_lm[1][ 4],in_lm[0][19],in_lm[1][19]);//nlm0[1] = in_lm[ 4] & in_lm[19];
	and_2shares(&nlm0[0][2],&nlm0[1][2],in_lm[0][ 9],in_lm[1][ 9],in_lm[0][ 1],in_lm[1][ 1]);//nlm0[2] = in_lm[ 9] & in_lm[ 1];
	and_2shares(&nlm0[0][3],&nlm0[1][3],in_lm[0][ 2],in_lm[1][ 2],in_lm[0][17],in_lm[1][17]);//nlm0[3] = in_lm[ 2] & in_lm[17];
	and_2shares(&nlm0[0][4],&nlm0[1][4],in_lm[0][ 5],in_lm[1][ 5],in_lm[0][16],in_lm[1][16]);//nlm0[4] = in_lm[ 5] & in_lm[16];
	and_2shares(&nlm0[0][5],&nlm0[1][5],in_lm[0][ 3],in_lm[1][ 3],in_lm[0][18],in_lm[1][18]);//nlm0[5] = in_lm[ 3] & in_lm[18];
	and_2shares(&nlm0[0][6],&nlm0[1][6],in_lm[0][ 6],in_lm[1][ 6],in_lm[0][15],in_lm[1][15]);//nlm0[6] = in_lm[ 6] & in_lm[15];
	and_2shares(&nlm0[0][7],&nlm0[1][7],in_lm[0][ 7],in_lm[1][ 7],in   [0][ 0],in   [1][ 0]);//nlm0[7] = in_lm[ 7] & in   [ 0];
	and_2shares(&nlm0[0][8],&nlm0[1][8],in_lm[0][ 8],in_lm[1][ 8],in_lm[0][12],in_lm[1][12]);//nlm0[8] = in_lm[ 8] & in_lm[12];

}
static void aes_sbox_non_linear_map1_2shares(bitslice_t nlm1[2][1], bitslice_t lm0[2][7]){
	and_2shares(&nlm1[0][0],&nlm1[1][0],lm0[0][2],lm0[1][2],lm0[0][4],lm0[1][4]);//nlm1[0] = lm0[2] & lm0[4];
}
static void aes_sbox_non_linear_map2_2shares(bitslice_t nlm2[2][2], bitslice_t lm0[2][7], bitslice_t lm1[2][3]){
	and_2shares(&nlm2[0][0],&nlm2[1][0],lm0[0][6],lm0[1][6],lm1[0][0],lm1[1][0]);//nlm2[0] = lm0[6] & lm1[0];
	and_2shares(&nlm2[0][1],&nlm2[1][1],lm1[0][2],lm1[1][2],lm1[0][1],lm1[1][1]);//nlm2[1] = lm1[2] & lm1[1];
}
static void aes_sbox_non_linear_map3_2shares(bitslice_t nlm3[2][5], bitslice_t in[2][8], bitslice_t in_lm[2][21], bitslice_t lm0[2][7], bitslice_t lm2[2][3]){
	and_2shares(&nlm3[0][0],&nlm3[1][0],lm0[0][5],lm0[1][5],lm2  [0][ 2],lm2  [1][ 2]);//nlm3[0] = lm0[5] & lm2  [ 2];
	and_2shares(&nlm3[0][1],&nlm3[1][1],lm2[0][1],lm2[1][1],in   [0][ 0],in   [1][ 0]);//nlm3[1] = lm2[1] & in   [ 0];
	and_2shares(&nlm3[0][2],&nlm3[1][2],lm2[0][0],lm2[1][0],in_lm[0][17],in_lm[1][17]);//nlm3[2] = lm2[0] & in_lm[17];
	and_2shares(&nlm3[0][3],&nlm3[1][3],lm2[0][1],lm2[1][1],in_lm[0][ 7],in_lm[1][ 7]);//nlm3[3] = lm2[1] & in_lm[ 7];
	and_2shares(&nlm3[0][4],&nlm3[1][4],lm2[0][0],lm2[1][0],in_lm[0][ 2],in_lm[1][ 2]);//nlm3[4] = lm2[0] & in_lm[ 2];
}
static void aes_sbox_non_linear_map4_2shares(bitslice_t nlm4[2][7], bitslice_t in_lm[2][21], bitslice_t lm2[2][3], bitslice_t lm3[2][4]){
	and_2shares(&nlm4[0][0],&nlm4[1][0],lm2[0][0],lm2[1][0],lm3  [0][ 1],lm3  [1][ 1]);//nlm4[0] = lm2[0] & lm3  [1];
	and_2shares(&nlm4[0][1],&nlm4[1][1],lm3[0][0],lm3[1][0],in_lm[0][14],in_lm[1][14]);//nlm4[1] = lm3[0] & in_lm[14];
	and_2shares(&nlm4[0][2],&nlm4[1][2],lm3[0][3],lm3[1][3],in_lm[0][12],in_lm[1][12]);//nlm4[2] = lm3[3] & in_lm[12];
	and_2shares(&nlm4[0][3],&nlm4[1][3],lm3[0][2],lm3[1][2],in_lm[0][16],in_lm[1][16]);//nlm4[3] = lm3[2] & in_lm[16];
	and_2shares(&nlm4[0][4],&nlm4[1][4],lm3[0][3],lm3[1][3],in_lm[0][ 8],in_lm[1][ 8]);//nlm4[4] = lm3[3] & in_lm[ 8];
	and_2shares(&nlm4[0][5],&nlm4[1][5],lm3[0][0],lm3[1][0],in_lm[0][10],in_lm[1][10]);//nlm4[5] = lm3[0] & in_lm[10];
	and_2shares(&nlm4[0][6],&nlm4[1][6],lm3[0][2],lm3[1][2],in_lm[0][ 5],in_lm[1][ 5]);//nlm4[6] = lm3[2] & in_lm[ 5];
}
static void aes_sbox_non_linear_map5_2shares(bitslice_t nlm5[2][8], bitslice_t in_lm[2][21], bitslice_t lm4[2][4]){
	and_2shares(&nlm5[0][0],&nlm5[1][0],lm4[0][2],lm4[1][2],in_lm[0][19],in_lm[1][19]);//nlm5[0] = lm4[2] & in_lm[19];
	and_2shares(&nlm5[0][1],&nlm5[1][1],lm4[0][0],lm4[1][0],in_lm[0][ 1],in_lm[1][ 1]);//nlm5[1] = lm4[0] & in_lm[ 1];
	and_2shares(&nlm5[0][2],&nlm5[1][2],lm4[0][3],lm4[1][3],in_lm[0][18],in_lm[1][18]);//nlm5[2] = lm4[3] & in_lm[18];
	and_2shares(&nlm5[0][3],&nlm5[1][3],lm4[0][1],lm4[1][1],in_lm[0][15],in_lm[1][15]);//nlm5[3] = lm4[1] & in_lm[15];
	and_2shares(&nlm5[0][4],&nlm5[1][4],lm4[0][2],lm4[1][2],in_lm[0][ 4],in_lm[1][ 4]);//nlm5[4] = lm4[2] & in_lm[ 4];
	and_2shares(&nlm5[0][5],&nlm5[1][5],lm4[0][1],lm4[1][1],in_lm[0][ 6],in_lm[1][ 6]);//nlm5[5] = lm4[1] & in_lm[ 6];
	and_2shares(&nlm5[0][6],&nlm5[1][6],lm4[0][0],lm4[1][0],in_lm[0][ 9],in_lm[1][ 9]);//nlm5[6] = lm4[0] & in_lm[ 9];
	and_2shares(&nlm5[0][7],&nlm5[1][7],lm4[0][3],lm4[1][3],in_lm[0][ 3],in_lm[1][ 3]);//nlm5[7] = lm4[3] & in_lm[ 3];
}

/**Masked bit slice implementation of aes_sbox.
* Supports out = in.
*/
static void aes_sbox_bitslice_2shares(bitslice_t out[2][8], bitslice_t in[2][8]){
	bitslice_t in_lm[2][21];
	bitslice_t nlm0[2][9];
	bitslice_t lm0[2][7];
	bitslice_t nlm1[2][1];
	bitslice_t lm1[2][3];
	bitslice_t nlm2[2][2];
	bitslice_t lm2[2][3];
	bitslice_t nlm3[2][5];
	bitslice_t lm3[2][4];
	bitslice_t nlm4[2][7];
	bitslice_t lm4[2][4];
	bitslice_t nlm5[2][8];
	bitslice_t lm5[2][24];
	aes_sbox_input_map(in_lm[0],in[0]);
	aes_sbox_input_map(in_lm[1],in[1]);
	aes_sbox_non_linear_map0_2shares(nlm0,in,in_lm);
	aes_sbox_linear_map0(lm0[0],in[0],in_lm[0],nlm0[0]);
	aes_sbox_linear_map0(lm0[1],in[1],in_lm[1],nlm0[1]);
	aes_sbox_non_linear_map1_2shares(nlm1,lm0);
	aes_sbox_linear_map1(lm1[0],lm0[0],nlm1[0]);
	aes_sbox_linear_map1(lm1[1],lm0[1],nlm1[1]);
	aes_sbox_non_linear_map2_2shares(nlm2,lm0,lm1);
	aes_sbox_linear_map2(lm2[0],lm0[0],lm1[0],nlm2[0]);
	aes_sbox_linear_map2(lm2[1],lm0[1],lm1[1],nlm2[1]);
	aes_sbox_non_linear_map3_2shares(nlm3,in,in_lm,lm0,lm2);
	aes_sbox_linear_map3(lm3[0],lm0[0],lm1[0],lm2[0],nlm3[0]);
	aes_sbox_linear_map3(lm3[1],lm0[1],lm1[1],lm2[1],nlm3[1]);
	aes_sbox_non_linear_map4_2shares(nlm4,in_lm,lm2,lm3);
	aes_sbox_linear_map4(lm4[0],lm0[0],lm2[0],lm3[0],nlm4[0]);
	aes_sbox_linear_map4(lm4[1],lm0[1],lm2[1],lm3[1],nlm4[1]);
	aes_sbox_non_linear_map5_2shares(nlm5,in_lm,lm4);
	aes_sbox_linear_map5(out[0],lm5[0],nlm3[0],nlm4[0],nlm5[0]);
	aes_sbox_linear_map5(out[1],lm5[1],nlm3[1],nlm4[1],nlm5[1]);
	aes_sbox_output_map(out[0]);//bitwise complement, apply to a single share
}

/**Fake masked bit slice implementation of aes_sbox.
* This allows to validate everything but the sbox.
*/
static void aes_sbox_bitslice_fake_2shares(bitslice_t out[2][8], bitslice_t in[2][8]){
	bitslice_t in1[8];
	xor_bitslice(in1,in[0],in[1],8);
	aes_sbox_bitslice(out[0],in1);
	memset(out[1],0,sizeof(bitslice_t)*8);
}

#if PARALLEL_OPS == 4
	#define BITMASK_0007 0x0007000700070007
	#define BITMASK_0008 0x0008000800080008
	#define BITMASK_000F 0x000F000F000F000F
	#define BITMASK_0044 0x0044004400440044
	#define BITMASK_0222 0x0222022202220222
	#define BITMASK_1111 0x1111111111111111
	#define BITMASK_2000 0x2000200020002000
	#define BITMASK_4400 0x4400440044004400
	#define BITMASK_7777 0x7777777777777777
	#define BITMASK_8880 0x8880888088808880
	#define BITMASK_8888 0x8888888888888888
#elif PARALLEL_OPS == 2
	#define BITMASK_0007 0x00070007
	#define BITMASK_0008 0x00080008
	#define BITMASK_000F 0x000F000F
	#define BITMASK_0044 0x00440044
	#define BITMASK_0222 0x02220222
	#define BITMASK_1111 0x11111111
	#define BITMASK_2000 0x20002000
	#define BITMASK_4400 0x44004400
	#define BITMASK_7777 0x77777777
	#define BITMASK_8880 0x88808880
	#define BITMASK_8888 0x88888888
#elif PARALLEL_OPS == 1
	#define BITMASK_0007 0x0007
	#define BITMASK_0008 0x0008
	#define BITMASK_000F 0x000F
	#define BITMASK_0044 0x0044
	#define BITMASK_0222 0x0222
	#define BITMASK_1111 0x1111
	#define BITMASK_2000 0x2000
	#define BITMASK_4400 0x4400
	#define BITMASK_7777 0x7777
	#define BITMASK_8880 0x8880
	#define BITMASK_8888 0x8888
#else
	#error "unsupported value for PARALLEL_OPS"
#endif
/**Bit slice implementation of aes_mixcolumn.
* Supports out = in.
*/
static void aes_mixcolumn_packed_bitslice(bitslice_t *out, const bitslice_t * const in){
	bitslice_t x0123[8];//use only the 4 lsb of each bitslice_t since we have 4 mixcolumn to process
	bitslice_t in_xtime2[8];
	bitslice_t next_xtime2[8];//in_xtime2 rotated right column wise
	unsigned int i,j;

	//Compute x0123 = byte_in[0]^byte_in[1]^byte_in[2]^byte_in[3]
	for(i=0;i<8;i++)
		x0123[i] = in[i];
	for(i=1;i<4;i++){
		for(j=0;j<8;j++){
			x0123[j] = (x0123[j]<<1)^in[j];
		}
	}
	//valid bits are the msb of each column, so bits 3, 7, 11, 15 of each bitslice_t
	//copy them to other bits in the same column
	for(j=0;j<8;j++){
			x0123[j] = x0123[j] & BITMASK_8888;
			x0123[j] = x0123[j]|(x0123[j]>>1)|(x0123[j]>>2)|(x0123[j]>>3);
	}

	//Compute in_xtime2
	in_xtime2[0] =         in[7];
	in_xtime2[1] = in[0] ^ in[7];
	in_xtime2[2] = in[1];
	in_xtime2[3] = in[2] ^ in[7];
	in_xtime2[4] = in[3] ^ in[7];
	in_xtime2[5] = in[4];
	in_xtime2[6] = in[5];
	in_xtime2[7] = in[6];

	//Compute next_xtime2
	for(j=0;j<8;j++){
			next_xtime2[j] = in_xtime2[j] & BITMASK_1111;
			next_xtime2[j] = (next_xtime2[j]<<3)|((in_xtime2[j]>>1)&BITMASK_7777);
	}

	//Compute byte_out[i] = x0123 ^ in[i] ^ in_xtime2[i] ^ next_xtime2[i]
	for(j=0;j<8;j++){
		out[j] = x0123[j] ^ in[j] ^ in_xtime2[j] ^ next_xtime2[j];
	}
}


static uint8_t f2(uint8_t x){
	return ((x << 1) ^ (((x >> 7) & 1) ? 0x1B : 0));
}
void xor_bitslice_2shares(bitslice_t out[2][8], bitslice_t a[2][8], bitslice_t b[2][8]){
	unsigned int i;
	for(i=0;i<8;i++){
		out[0][i] = a[0][i] ^ b[0][i];
	}
	for(i=0;i<8;i++){
		out[1][i] = a[1][i] ^ b[1][i];
	}
}
void xor_byte_cste_single_slice_2shares(bitslice_t out[2][8], bitslice_t a[2][8], uint8_t cste, unsigned int bitslice){
	unsigned int i;
	bitslice_t c;
	bitslice_t one = 1<<bitslice;
	for(i=0;i<8;i++){
		c = cste & (1<<i) ? one : 0;
		out[0][i] = a[0][i] ^ c;
	}
}
void xor_byte_cste_multi_slice_2shares(bitslice_t out[2][8], bitslice_t a[2][8], uint8_t cste, bitslice_t bitslice_mask){
	unsigned int i;
	bitslice_t c;
	bitslice_t one = bitslice_mask;
	for(i=0;i<8;i++){
		c = cste & (1<<i) ? one : 0;
		out[0][i] = a[0][i] ^ c;
	}
}
static void update_encrypt_key_128_packed_bitslice_2shares(bitslice_t k[2][8], uint8_t *rc ){
	bitslice_t tmp[2][8];
	unsigned int i,c;

	//Compute the following:
  //k[0] ^= s_box(k[13]) ^ *rc;
	//k[1] ^= s_box(k[14]);
	//k[2] ^= s_box(k[15]);
	//k[3] ^= s_box(k[12]);
  aes_sbox_bitslice_2shares(tmp,k);
	//xor_byte_cste_single_slice_2shares(tmp,tmp,*rc,13);
	xor_byte_cste_multi_slice_2shares(tmp,tmp,*rc,BITMASK_2000);

	for(i=0;i<8;i++){
		tmp[0][i]=((tmp[0][i]>>13) & BITMASK_0007)|(((tmp[0][i]>>12)<<3) & BITMASK_0008);
		tmp[1][i]=((tmp[1][i]>>13) & BITMASK_0007)|(((tmp[1][i]>>12)<<3) & BITMASK_0008);
	}
	xor_bitslice_2shares(k,k,tmp);

	*rc = f2( *rc );

	//Compute the following:
  //k[cc + 0] ^= k[cc - 4];
	//k[cc + 1] ^= k[cc - 3];
  //k[cc + 2] ^= k[cc - 2];
  //k[cc + 3] ^= k[cc - 1];
	for(c=1;c<4;c++){
		for(i=0;i<8;i++){
			tmp[0][i]=(BITMASK_000F<<(c*4)) & (k[0][i]<<4);
			k[0][i]^=tmp[0][i];
			tmp[1][i]=(BITMASK_000F<<(c*4)) & (k[1][i]<<4);
			k[1][i]^=tmp[1][i];
		}
	}
}

void sec_aes128_enc_packed_bitslice(bitslice_t out[2][8], bitslice_t in[2][8], bitslice_t key[2][8]){
	unsigned int i,j;
	uint8_t r, rc = 1;
	bitslice_t tmp;
	memcpy(out,in,2*8*sizeof(bitslice_t));
	for( r = 1 ; r < 11 ; ++r ){
		//add key
		xor_bitslice_2shares(out,out,key);
		//sub byte
		aes_sbox_bitslice_2shares(out,out);
		//shift row
		// in             00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
		// invariant      00          04          08          12
		// rotate left 12    01          05          09          13
		// rotate left 8        02          06          10          14
		// rotate left 4           03          03          11          15
		for(i=0;i<2;i++){//for each share
			for(j=0;j<8;j++){//for each bit in a byte
				tmp = 0;
				tmp |=  BITMASK_1111 &  out[i][j];//invariant
				tmp |= (BITMASK_2000 & (out[i][j]<<12))|(BITMASK_0222 & (out[i][j]>> 4));//rotate left 12
				tmp |= (BITMASK_4400 & (out[i][j]<< 8))|(BITMASK_0044 & (out[i][j]>> 8));//rotate left  8
				tmp |= (BITMASK_8880 & (out[i][j]<< 4))|(BITMASK_0008 & (out[i][j]>>12));//rotate left  4
				out[i][j]=tmp;
			}
		}
		if(r!=10) {
			//mix column
			aes_mixcolumn_packed_bitslice(out[0],out[0]);
			aes_mixcolumn_packed_bitslice(out[1],out[1]);
		}
		//keyschedule
		update_encrypt_key_128_packed_bitslice_2shares( key, &rc );
	}
  //add key
	xor_bitslice_2shares(out,out,key);
}

void sec_aes128_enc_packed_bitslice_wrapper(uint8_t out[16], const uint8_t in[16], const uint8_t key[16]){
	unsigned int i;
	bitslice_t bs_out[2][8];
	bitslice_t bs_in[2][8];
	bitslice_t bs_key[2][8];
	uint8_t tmp[16];

	bytes_to_packed_bitslice(bs_in[0],in,16);
	randomize_bitslice(bs_in[1], 8);
	xor_bitslice(bs_in[0], bs_in[0], bs_in[1], 8);

	bytes_to_packed_bitslice(bs_key[0],key,16);
	randomize_bitslice(bs_key[1], 8);
	xor_bitslice(bs_key[0], bs_key[0], bs_key[1], 8);

	sec_aes128_enc_packed_bitslice(bs_out,bs_in,bs_key);

	packed_bitslice_to_bytes(out,bs_out[0],16);
	packed_bitslice_to_bytes(tmp,bs_out[1],16);

	for(i=0;i<16;i++)
		out[i]^=tmp[i];
}

void sec_aes128_enc_packed_bitslice_wrapper_multi(
	uint8_t out[PARALLEL_OPS][16],
	uint8_t in [PARALLEL_OPS][16],
	uint8_t key[PARALLEL_OPS][16],
	unsigned int n_blocks
){
	unsigned int i,block;
	bitslice_t bs_out[2][8];
	bitslice_t bs_in[2][8];
	bitslice_t bs_key[2][8];
	uint8_t tmp[PARALLEL_OPS][16];

	//Convert input to bitslice representation, store that in the first share
	bytes_to_packed_bitslice(bs_in[0],in[0],16);
	bytes_to_packed_bitslice(bs_key[0],key[0],16);
	for(block=1;block<n_blocks;block++){
		unsigned int offset = 16*block;
		insert_bytes_to_packed_bitslice(bs_in[0],in[block],16,offset);
		insert_bytes_to_packed_bitslice(bs_key[0],key[block],16,offset);
	}

	//load second share with random bits
	randomize_bitslice(bs_in[1], 8);
	randomize_bitslice(bs_key[1], 8);

	//adjust the first share
	xor_bitslice(bs_in[0], bs_in[0], bs_in[1], 8);
	xor_bitslice(bs_key[0], bs_key[0], bs_key[1], 8);

	//compute all blocks
	sec_aes128_enc_packed_bitslice(bs_out,bs_in,bs_key);

	//convert results to regular representation (but still on 2 shares)
	packed_bitslice_to_bytes((uint8_t*)out,bs_out[0],16*n_blocks);
	packed_bitslice_to_bytes((uint8_t*)tmp,bs_out[1],16*n_blocks);

	//reduce to plain representation in the output buffers
	for(block=0;block<n_blocks;block++){
		for(i=0;i<16;i++){
			out[block][i]^=tmp[block][i];
		}
	}
}

//development/debug stuff

/** Test the masked and function
 */
static unsigned int test_and_2shares(void){
	unsigned int i;
	unsigned int error=0;
	for(i=0;i<32;i++){
		bitslice_t a0,a1,b0,b1,out0,out1,a,b,out;
		a0 = i & 1 ? -1 : 0;
		a1 = i & 2 ? -1 : 0;
		b0 = i & 4 ? -1 : 0;
		b1 = i & 8 ? -1 : 0;
		a = a0^a1;
		b = b0^b1;
		if(i & 0x10){//replace ordered values by random mask for the last 16 loops
			a0 = get_random_bitslice();
			b0 = get_random_bitslice();
			a1 = a ? ~a0 : a0;
			b1 = b ? ~b0 : b0;
		}
		//tweak the values in such way that we test the full truth table within each operation (but different bits each time)
		a0^=0x00112233;a^=0x00112233;
		b0^=0x04488990;b^=0x04488990;
		and_2shares(&out0,&out1,a0,a1,b0,b1);
		out = out0 ^ out1;
		if(out != (a&b)){
			error++;
		}
	}
	return error;
}
/*
static void aes_encrypt_key_schedule_128_packed_bitslice_2shares(bitslice_t key[2][8]){
	uint8_t r, rc = 1;
	for( r = 1 ; r < 11 ; ++r ){
		update_encrypt_key_128_packed_bitslice_2shares( key, &rc );
	}
}
extern bitslice_t spy[2][8];
void spy_loop(void){
	bitslice_t out[2][8];
	bitslice_t in[2][8];
	unsigned int i;
	memset(in,0, sizeof(in));
	for(i=0;i<1024*1024/4;i++){
		int j;
		aes_sbox_bitslice_2shares(out,in);
		for(j=0;j<8;j++) spy[0][j]=out[0][j];
		for(j=0;j<8;j++) spy[1][j]=out[1][j];
	}
}
*/
