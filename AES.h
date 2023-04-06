#pragma once
#include<malloc.h>
#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#ifndef AES_H
#define AES_H
using namespace std;
typedef unsigned char uchar;
typedef unsigned int uint;

// Key expansion 
void RotWord(uchar key[][4]);
void SubWord(uchar key[][4]);
void KeyExpansion(uchar * key);

// 加密过程函数 
void SubBytes(uchar state[][4]);
void ShiftRows(uchar state[][4]);
void MixColumns(uchar state[][4]);
void AddRoundKey(uchar state[][4], uchar key[][4]);
uchar * encrypt(uchar * cipher, uchar * key);

uchar XTime(uchar x);
uchar FFmul(uchar a, uchar b);

// 解密过程函数 
void InvSubBytes(uchar state[][4]);
void InvShiftRows(uchar state[][4]);
void InvMixColumns(uchar state[][4]);
uchar * decrypt(uchar * cipher, uchar * key);


// 最后 Encryt and Decrypt 函数
uchar * Cipher(uint * length, uchar * cipher, uchar * key);
uchar * InvCipher(uint * length, uchar * cipher, uchar * key);


//补充：自动生成初始对称密钥
const unsigned char allChar[17] = "0123456789abcdef";
void generateStr(unsigned char *daes, unsigned int len);
#endif