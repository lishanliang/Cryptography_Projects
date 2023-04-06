#pragma once
#include"BigInt.h"
class RSA
{
public:
	RSA();
	~RSA();
	void init(unsigned int n);//��ʼ��������nλ���ȵ�p,q;������ҵ��Կ����N����Ϊ256λλ����Ӧp,qӦ��128λ

	friend void test();
	BigInt encryptByPu(const BigInt& m);//˽Կ����
	BigInt decodeByPr(const BigInt& c);//��Կ����

	BigInt encryptByPr(const BigInt& m);//��Կ����
	BigInt decodeByPu(const BigInt& m);//˽Կ����
private:
	BigInt createOddNum(unsigned int n);//���ɳ���Ϊn������
	bool isPrime(const BigInt& a, const unsigned int k);//�ж�����
	BigInt createPrime(unsigned int n, int it_cout);//���ɳ���Ϊn������
	void createExp(const BigInt& ou);//��һ��ŷ���������ɹ�Կ��˽Կָ��
	BigInt createRandomSmallThan(const BigInt& a);//����С��
	friend ostream& operator <<(ostream& out, const RSA& RSA)//���
	{
		out << "N:" << RSA.N << "\n";
		out << "p:" << RSA._p << "\n";
		out << "q:" << RSA._q << "\n";
		out << "e:" << RSA.e << "\n";
		out << "d:" << RSA._d;
		return out;
	}
public:
	BigInt e, N;//��Կ
private:
	BigInt _d;//˽Կ
	BigInt _p, _q;//
	BigInt _ol;//ŷ����
};
