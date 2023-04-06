#pragma once
#include"BigInt.h"
class RSA
{
public:
	RSA();
	~RSA();
	void init(unsigned int n);//初始化，产生n位长度的p,q;本次作业密钥长度N设置为256位位，对应p,q应该128位

	friend void test();
	BigInt encryptByPu(const BigInt& m);//私钥加密
	BigInt decodeByPr(const BigInt& c);//公钥解密

	BigInt encryptByPr(const BigInt& m);//公钥加密
	BigInt decodeByPu(const BigInt& m);//私钥解密
private:
	BigInt createOddNum(unsigned int n);//生成长度为n的奇数
	bool isPrime(const BigInt& a, const unsigned int k);//判断素数
	BigInt createPrime(unsigned int n, int it_cout);//生成长度为n的素数
	void createExp(const BigInt& ou);//从一个欧拉数中生成公钥、私钥指数
	BigInt createRandomSmallThan(const BigInt& a);//创建小数
	friend ostream& operator <<(ostream& out, const RSA& RSA)//输出
	{
		out << "N:" << RSA.N << "\n";
		out << "p:" << RSA._p << "\n";
		out << "q:" << RSA._q << "\n";
		out << "e:" << RSA.e << "\n";
		out << "d:" << RSA._d;
		return out;
	}
public:
	BigInt e, N;//公钥
private:
	BigInt _d;//私钥
	BigInt _p, _q;//
	BigInt _ol;//欧拉数
};
