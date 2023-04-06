#pragma once
#include<iostream>
#include<vector>
#include"BigInt.h"
using  std::string;
using namespace std;
#ifndef _DES_H
#define _DES_H
#include <iostream>
#include<string>
using namespace std;

//���ݳ�ʼ�û���
int T1[8][8] = { 58,50,42,34,26,18,10,2,
60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,
59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,
63,55,47,39,31,23,15,7 };

//��Կ��ʼ�û���
int T2[8][7] = { 57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
3,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4 };

//��Կѭ������λ����

int T3[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

//��Կѹ���û���

int T4[8][6] = { 14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32 };

//������չ��
int T5[8][6] = { 32,1,2,3,4,5,
4,5,6,7,8,9,
8,9,10,11,12,13,
12,13,14,15,16,17,
16,17,18,19,20,21,
20,21,22,23,24,25,
24,25,26,27,28,29,
28,29,30,31,32,1 };

//S���û���
int S[8][4][16] = { { { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 } },
{ { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 } },
{ { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 } },
{ { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 } },
{ { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 } },
{ { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 } },
{ { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 } },
{ { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 } } };

//P���û���
int P[4][8] = { 16,7,20,21,
29,12,28,17,
1,15,23,26,
5,18,31,10,
2,8,24,14,
32,27,3,9,
19,13,30,6,
22,11,4,25 };


//�����û���
int T6[8][8] = { 40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25 };

/**

*�����û����� 64λ->64λ

*����˵����sΪ������һ��ѭ���õ���64Ϊ����

*����ֵΪ���Ļ�����

*/
string final_permutation(string s)
{
	string rs = "";
	for (int i = 0; i<8; i++)
	{
		for (int j = 0; j<8; j++)
		{
			rs += s[T6[i][j] - 1];
		}
	}
	return rs;
}

/**

*P���û����� 32λ->32λ

*����˵����sΪS�е����

*/
string P_box(string s)
{
	string rs = "";
	for (int i = 0; i<4; i++)
	{
		for (int j = 0; j<8; j++)
		{
			rs += (s[P[i][j] - 1]);
		}
	}
	return rs;
}

/**
S���û����� 48λ->32λ
����˵����sΪ48λ����
����ֵΪ32λ
*/
string S_box(string s)
{
	string rs = "";
	string s1;
	int k1, k2;//S�е��кź��к�
	int h = 1;//����ʹ���Ǹ�S��
	for (int i = 0; i <= 42; i = i + 6, h++)
	{
		k1 = (s[i] - '0') * 2 + (s[i + 5] - '0') * 1;
		k2 = (s[i + 1] - '0') * 8 + (s[i + 2] - '0') * 4 + (s[i + 3] - '0') * 2 + (s[i + 4] - '0') * 1;
		int x = S[h - 1][k1][k2];
		s1 = "";
		int y = 8;
		for (int j = 1; j <= 4; j++)
		{
			if (x<y)
			{
				s1 += "0";
				y /= 2;
			}
			else
			{
				s1 += "1";
				x = x%y;
				y /= 2;
			}
		}
		rs += s1;
	}
	return rs;
}

/**

������㺯��
Ҫ��λ����ͬ

*/
string XOR(string s1, string s2)
{
	string rs = "";
	for (int i = 0; i<s1.length() && i<s2.length(); i++)
	{
		rs += ((s1[i] - '0') ^ (s2[i] - '0')) + '0';
	}
	return rs;
}

/**
������չ���� 32->48
����˵����sΪ���ݵ��Ұ벿�� 32λ
��չ��48λ�����

*/
string plaintext_righthalf_extended_permutation(string s)
{
	string rs = "";
	for (int i = 0; i<8; i++)
	{
		for (int j = 0; j<6; j++)
		{
			rs += s[T5[i][j] - 1];
		}
	}
	return rs;
}

/**

��Կѹ���û����� 56λ->48λ
����˵����sΪ56Ϊ����Կ
���Ϊ48λ������Կ

*/
string secret_key_compression_replacement(string s)
{
	string rs = "";
	for (int i = 0; i<8; i++)
	{
		for (int j = 0; j<6; j++)
		{
			rs += s[T4[i][j] - 1];
		}
	}
	return rs;
}

/**

��Կѭ�����ƺ��� 56λ->56λ

����˵����kΪ����λ�� sΪ��Կ

����ֵλ������

*/
string secret_ket_left_move(int k, string s)//��Կѭ������kλ
{
	string s1 = s.substr(0, 28);
	string s2 = s.substr(28, 28);
	string rs = s1.substr(k, 28 - k) + s1.substr(0, k) + s2.substr(k, 28 - k) + s2.substr(0, k);
	return rs;
}

/**

*��Կ��ʼ�û����� 64λ->58λ

*����˵����sΪ64λ�ĳ�ʼ��Կ

*����ֵΪ58λ

*/
string secret_key_initial_permutation(string s)
{
	string rs = "";
	for (int i = 0; i<8; i++)
	{
		for (int j = 0; j<7; j++)
		{
			rs += s[T2[i][j] - 1];
		}
	}
	return rs;
}

/**

*���ĳ�ʼ�û����� 64λ->64λ

*����˵����sΪ��ʼ���� 64λ

*����ֵΪ6λ

*/
string plaintext_initial_permutation(string s)//���ĳ�ʼ�û�
{
	string rs = "";
	for (int i = 0; i<8; i++)
	{
		for (int j = 0; j<8; j++)
		{
			rs += s[T1[i][j] - 1];
		}
	}
	return rs;
}

/**

*16����ת2���ƺ���

*����˵����sΪ16�����ַ���

*����Ϊ2�����ַ���

*/
string H(string s)
{
	string s1;
	string rs = "";
	for (int i = 0; i<s.length(); i++)
	{
		int x;
		if (s[i] >= '0'&&s[i] <= '9')
		{
			x = s[i] - '0';
		}
		else
		{
			x = s[i] - 'A' + 10;
		}
		s1 = "";
		int y = 8;
		for (int j = 1; j <= 4; j++)
		{
			if (x<y)
			{
				y /= 2;
				s1 += "0";
			}
			else
			{
				s1 += "1";
				x = x%y;
				y = y / 2;
			}
		}
		rs += s1;
	}
	return rs;
}

/**

*2����ת16���ƺ���

*strΪ2�����ַ���

*����ֵΪ16�����ַ���

*/
string G(string str)
{
	string rs = "";
	char temp;
	for (int i = 0; i <= str.length() - 4; i = i + 4)
	{
		int x = (str[i] - '0') * 8 + (str[i + 1] - '0') * 4 + (str[i + 2] - '0') * 2 + str[i + 3] - '0';

		if (x >= 10)
		{
			temp = (char)(x - 10 + 'a');
		}
		else
		{
			temp = (char)(x + '0');
		}
		rs += temp;
	}
	return rs;
}

/**

*��װ����f

*����˵��������32λ���ݺ�48λ������Կ ����һ��32λ�����

*str1:32λ����  str2:48λ������Կ

*����ֵ32λ

*/

string f(string str1, string str2)
{
	string expendR = plaintext_righthalf_extended_permutation(str1);
	//cout << "32λ������չΪ48λ���:" << expendR << endl;

	string rs = XOR(expendR, str2);
	//cout << "��Կ����չ���������:" << rs << endl;

	rs = S_box(rs);
	//cout << "S��������(48->32):" << rs << endl;

	rs = P_box(rs);
	//cout << "P��������(32->32):" << rs << endl;

	return rs;
}

/**

*����Կ���ɺ���

*����˵����sΪ��������Կ

*����16������Կ

*/
string Keys[20];

void generateKeys(string s)
{
	s = secret_key_initial_permutation(s);

	for (int i = 1; i <= 16; i++)
	{
		s = secret_ket_left_move(T3[i - 1], s);
		Keys[i] = secret_key_compression_replacement(s);
		//cout << "K" << i << ":" << Keys[i] << endl;
	}
	//cout << endl;
}

/**

*DES���ܺ��� 64λ->64λ

*����˵����str1Ϊ64λ�ĸ�������

*����ֵΪ64λ������

*/
string encrypt(string str1)
{
	//��һ��:���ĳ�ʼ�û� 64->64
	str1 = plaintext_initial_permutation(str1);
	//cout << "���ĳ�ʼ�û����(64->64):" << str1 << endl << endl;

	//�ڶ���:���ݷ���
	string left = str1.substr(0, 32);
	string right = str1.substr(32, 32);
	//cout << "L0:" << left << endl;
	//cout << "R0:" << right << endl << endl;

	string newleft;

	//������:16�ֵ���
	for (int i = 1; i <= 16; i++)
	{
		//cout << "��" << i << "�ε���" << endl;
		newleft = right;

		right = XOR(left, f(right, Keys[i]));

		left = newleft;

		//cout << "L[" << i << "]:" << left << endl;
		//cout << "R[" << i << "]:" << right << endl << endl;
	}

	//���Ĳ�:�ϲ����� ע��λR16L16
	string rs = right + left;
	//cout << "R16L16:" << rs << endl << endl;

	//��β�û�
	rs = final_permutation(rs);
	//cout << "�����û����:" << rs << endl << endl;
	return rs;

}
/**

*���ܺ���

*strΪ����

*�������

*/
string decrypt(string str)
{
	//�����ĵ������Ľ��г�ʼ�����û�
	str = plaintext_initial_permutation(str);
	//cout << "���ĵ������ĳ�ʼ�û����(64->64):" << str << endl << endl;

	//����
	string left = str.substr(0, 32);
	string right = str.substr(32, 32);
	//cout << "L0:" << left << endl;
	//cout << "R0:" << right << endl << endl;

	string newleft;

	//���������Կʹ�� 16�ֵ���
	for (int i = 16; i >= 1; i--)
	{
		//cout << "��" << 17 - i << "�ε���" << endl;

		newleft = right;
		right = XOR(left, f(right, Keys[i]));
		left = newleft;

		//cout << "L[" << 17 - i << "]:" << left << endl;
		//cout << "R[" << 17 - i << "]:" << right << endl << endl;
	}

	//�ϲ�
	string rs = right + left;
	//cout << "R16L16:" << rs << endl << endl;

	//����û�
	rs = final_permutation(rs);
	//cout << "�����û����:" << rs << endl << endl;

	return rs;
}
//������ַ�����һ����16���ַ���������Ҫһ�������������ַ���Ϊ16���ַ����ַ������ֱ���ܺ�������һ���������
string des_encryption(string s1, string s2) {
	//string str2 = s2;
	//string str1 = s1;
	long long len = s1.length();
	int num = len / 16 ;
	string vec[1000];
	string des_c[1000];
	for (int i = 0; i < num; i++) {
		vec[i]=s1.substr(16*i,16);
		vec[i] = H(vec[i]);
	}
	s2 = H(s2);
	generateKeys(s2);
	for (int i = 0; i < num; i++) {
		des_c[i] = G(encrypt(vec[i]));
	}
	string des_encrypt_c;
	for (int i = 0; i < num; i++) {
		des_encrypt_c+=des_c[i];
	}
	//cout << des_encrypt_c << endl;
	return des_encrypt_c;
}
//���ܺ�����
string des_decryption(string s1, string s2) {
	//string str2 = s2;
	//string str1 = s1;
	long long len = s1.length();
	int num = len / 16;
	string vec[1000];
	string des_c[1000];
	for (int i = 0; i < num; i++) {
		vec[i] = s1.substr(16 * i, 16);
		vec[i] = H(vec[i]);
	}
	s2 = H(s2);
	generateKeys(s2);
	for (int i = 0; i < num; i++) {
		des_c[i] = G(decrypt(vec[i]));
	}
	string des_decrypt_c;
	for (int i = 0; i < num; i++) {
		des_decrypt_c += des_c[i];
	}
	//cout << des_decrypt_c << endl;
	return des_decrypt_c;
}
int main9()
{	
	string s1 = "8a48f3736be41e785f65530f9e74ca81fae61dc93e2345e22c8675b25d46b2102c1611edee3747193017fa51fea3f0367b8065da7b6c336c08b6adb8687bcdb003315d990a0cf659c9756b73c62f0c8ad7748d1822a629875cefb44a649f06c28a4823736be41e785f65530f9e74ca81fae61dc93e2345e22c8675b25d46b2102c1611edee3747193017fa51fea3f0367b8065da7b6c336c08b6adb8687bcdb003315d990a0cf659c9756b73c62f0c8ad7748d1822a629875cefb44a649f06c0d53ebdf79a51cadb32aa356692a1bd7ec4bd1429dfd333038b56a374168f485";//���� 16����
	if (s1.length() % 16 != 0) {//���Ĳ���16�ı�����Ҫ���㣻
		int n = s1.length() % 16;
		vector<char>a;
		for (int i = 0; i < 16-n; i++)s1 += '0';
	}
	string str1 = s1;
	string str2 = "133457799BBCDFF1";//��Կ16����
	cout <<str1<< endl;
	string str3=des_encryption(str1, str2);
	string str4 = des_decryption(str3, str2);
	cout << endl;
	string temp = str1;//����ʮ�����Ƶ������Ա������֤�㷨��ȷ��					   
	system("pause");
	return 0;
}
#endif