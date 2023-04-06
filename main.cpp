#include<iostream>
#include<ctime>
#include<fstream>
#include <bitset>
#include <windows.h>
#include<string>
#include"BigInt.h"
#include"RSA.h"
#include"AES.h"
#include"DES.h"
#include"SHA.h"
#include"MD5.h"
using namespace std;
int main()
{   
	//-------------���ͷ�A������Կ��˽Կ�����շ�B������Կ��˽Կ-------------
	cout << "Please wait for generating UKA and UKB" << endl;
	RSA rsa_A,rsa_B;
	rsa_A.init(128);//N=256;
	Sleep(1000);
	rsa_B.init(128);//N=256;
	cout << "���ͷ�A�Ĺ�ԿUKAΪ��" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
	cout << "���ͷ�B�Ĺ�ԿUKBΪ��" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;

	const unsigned int str_len = 16;
	unsigned char sym_key1[str_len + 1] = {};
	generateStr(sym_key1, str_len);
	string sym_key((char *)sym_key1);
	cout << "������ɵĶԳ���Կ��" << sym_key << endl;
	/*ѡ��������ͣ�����1Ϊ�ַ������ܣ�����2ΪΪ�ļ����ܣ�*/
	int choice=0;//choice=1Ϊ�ַ������ܣ�choice=2ΪΪ�ļ�����
	while(1)
	{
		printf("��ѡ��������ͣ�\n");
		printf("����1��ʾ�������ַ���(�����㷨��ѡ):ǩ��->����->����->��֤hash; \n");
		printf("����2��ʾ���ı��ļ����ַ�(�Գ��㷨��DES��:ǩ��->����->����->��֤hash; \n");
		printf("����3��ʾ�������ļ�(�Գ��㷨��AES��:����->����->��֤����� \n");
		cin >> choice;
		cin.get();
		if (choice == 1 || choice == 2||choice==3)break;
		else printf("��ѡ����ȷ�Ĳ�������!\n");
	}
	//----------���ַ�������-------------
	if (choice == 1)
	{
		//������Ҫ���ܵ��ַ���
		printf("��������Ҫ���ܵ��ַ���: \n");
		string str1 = "";
		string hash = "";
		getline(cin, str1);
		string str = str1;
		if (str.length() % 16 != 0) {//�����Ĳ���16�ı�����Ҫ���㣻
			int n = str.length() % 16;
			cout << "����λ������16�ı�������Ҫ����λ��(���㲿����0���㣩��" << endl;
			for (int i = 0; i < 16 - n; i++)str += '0';
			cout << "����λ���������:" << endl;
			cout << str << endl;
		}
		//-------------ѡ��hash����������1��ʾSHA�㷨������2��ʾMD5�㷨-------------
		int cho1 = 0;//cho1=1��ʾSHA�㷨��cho1=2��ʾMD5�㷨
		while (1)
		{
			cout<<"��ѡ��hash������1��ʾSHA�㷨��2��ʾMD5�㷨:  "<<endl;
			cin >> cho1;
			cin.get();
			if (cho1 == 1 || cho1 == 2)break;
			else cout << "��ѡ����ȷ���㷨����!" << endl;
		}
		if (cho1 == 1)
		{
			cout << "ԭʼ���ģ�" << str << endl;
			cout << "Please wait for several seconds��" << endl;
			hash = sha1(str); //hashֵΪ160bit	
			Sleep(3000);//��Ҫsha1����ʱ���ӳ�
			cout << "SHA����������HASHֵ��" << hash<< endl;

		}
		if (cho1 == 2)
		{
			//cout << "���ģ�" << str << endl;	
			hash = getMD5Code(str); //hashֵΪ128bit
			cout << "MD5������HASHֵ��" << hash << endl;
		}
		//-------------���ͷ���hash���м���-------------//
		BigInt rsa_plain(hash);//��hashֵ��ʼ������
		BigInt rsa_c = rsa_A.encryptByPr(rsa_plain);//˽ԿԿ���ܺ�����Ϊrsa_c
		BigInt rsa_m = rsa_A.decodeByPu(rsa_c);//��Կ���ܺ�����Ϊ rsa_m
		//cout << "���ͷ�A�Ĺ�ԿUKAΪ��" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
		cout << "ǩ�����hash:" << rsa_c << endl;
		cout << endl;
	//	cout << "��֤ǩ����hash:" << rsa_m << endl;
	//	cout << endl;

		//��ǩ�����hash�������ĺ�
		cout << "��ǩ�����hash�������ĺ������"<<endl;
		string m_and_hash = str + rsa_c.get_str(rsa_c);
		cout << m_and_hash << endl;
		cout << endl;

		//-------------��ѡ��ѡ��ԳƼ����㷨��1��ʾDES�����㷨;2��ʾAES�㷨-------------
		int cho2 = 0;//cho2=1��ʾDES�����㷨��Ϊ2��ʾAES�㷨
		while (1)
		{
			cout << "��ѡ��ԳƼ����㷨��1��ʾDES�㷨��2��ʾAES�㷨:  " << endl;
			cin >> cho2;
			cin.get();
			if (cho2 == 1 || cho2 == 2)break;
			else cout << "��ѡ����ȷ���㷨����!" << endl;;
		}
		if (cho2 == 1)
		{
			cout << "ѡ��ĶԳƼ����㷨��DES" << endl;
			//..........����Ԥ������BigInt ��Ϊstring����...........//
			string des_key = sym_key;//des��Կ16λ16��������
			string plain_hash =m_and_hash.data();//���ļ�hashֵ
			uint len3 = plain_hash.length();
			printf("Length of decrypted len3 = %d\n", len3);
			printf("-----------------------------DES Encryption Over-------------------------------\n");
			printf("\n");
			printf("----���ͷ����ͣ�---------------------UKB(des_key)------------\n");
			BigInt rsa_des_key(des_key);//��des_keyֵ��ʼ������		
										//cout << "���շ�B�Ĺ�ԿUKAΪ��" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
			BigInt rsa_des_key_c = rsa_B.encryptByPu(rsa_des_key);//���շ�B��ԿԿ���ܺ�����Ϊrsa_des_key_m
																  //BigInt rsa_des_key_m = rsa_B.decodeByPr(rsa_des_key_c);//
			cout << "���ܺ��des_key:" << rsa_des_key_c << endl;
			cout << endl;
			cout << endl;
			printf("----���ͷ����ͣ�-----------------------des_key(Plain_hash)------------\n");
			string des_plain_hash = des_encryption(plain_hash, des_key);;//���ܺ��plain_hash																					
			cout << "des_key(Plain_hash):" << des_plain_hash << endl;
			cout << endl;
			cout << endl;
			printf("-------------------------���շ�B:   RKB(UKB(des_key))----------------------------\n");
			BigInt des_key_B = rsa_B.decodeByPr(rsa_des_key_c);
			cout << "���շ����ܺ��des_key:" << des_key_B << endl;
			cout << endl;
			string des_key_B_str = des_key_B.get_str(des_key_B);//��BigInt����des_keyת��Ϊstring����
			printf("-------------------------���շ�B:   des_key(des_plain_hash)---------------------\n");
			string de_des_plain_hash = des_decryption(des_plain_hash, des_key_B_str);//des���ܵ�plain_hash
			printf("Decrypted plain_hash: ");
			cout << de_des_plain_hash << endl;
			printf("\n");
			printf("-------------------------���շ�B:  ��des_plain_hash��ΪM��EKA(hash)--------------------\n");//EK(hash)Ϊ�̶���64λ�ַ�
			string ss = de_des_plain_hash;//��uchar ��(M)||(hash)ת��Ϊstring�����������������
			long long lens = ss.length();
			string ss_1 = ss.substr(lens - 64, 64);//EKA(hash)Ϊ���64λ
			cout << "EKA(hash):" << ss_1 << endl;
			string ss_2 = ss.substr(0, lens - 64);
			cout << "plain_txt:" << ss_2 << endl;
			cout << endl;
			printf("-------------------------���շ�B:  UKA((EKA(hash))���hash--------------------\n");
			BigInt hash_final(ss_1);//���ܻ��(EKA(hash)Ϊss_1
			BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
			cout << "hash:" << hash_B_get << endl;
			string hash_B_1 = hash_B_get.get_str(hash_B_get);//��BigIntת��Ϊstring,Ϊ������hash�Ƚ���׼��
			cout << hash_B_1 << endl;
			printf("-------------------------���շ�B:  hash(plain_txt)���hash--------------------\n");
			if (cho1 == 1)//cho1=1��Ϊhash����ΪSHA;
			{
				cout << "hash����ΪSHA" << endl;
				string hash_B_2 = sha1(ss_2);//���ܻ������Ϊss_2
				Sleep(3000);//��2��			
				cout << "hash(plain_txt):" << endl;
				cout<<hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "����hashֵһ�£����ܹ��̽�����" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "����hashֵ��һ�£���������Bug��" << endl;
				}
			}
			if (cho1 == 2)//cho1=2��Ϊhash����ΪMD5;
			{
				cout << "hash����ΪMD5" << endl;
				string hash_B_2 = getMD5Code(ss_2);//���ܻ������Ϊss_2
				cout << "hash(plain_txt):" << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "����hashֵһ�£����ܹ��̽�����" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "����hashֵ��һ�£���������Bug��" << endl;
				}
			}
		}
		if (cho2 == 2)
		{
			cout << "ѡ��ĶԳƼ����㷨��AES" << endl;
			//..........����Ԥ������BigInt ��Ϊuchar����...........//
		    char* temp;
			temp = (char *)m_and_hash.data();//���ļ�hashֵ
			uchar * plain_hash;
			plain_hash = reinterpret_cast<uchar *>(temp);
			//cout << "plain_hash:" << plain_hash << endl;

			//..........�ԳƼ��ܹ��̣��ֱ����plain_hash �͹�Կ��UKa_e��UKa_N)........../
			string aes_key = sym_key;
			uint len3 = strlen((const char*)plain_hash)+1;
			printf("Length of decrypted len3 = %d\n", len3);
			printf("-----------------------------AES Encryption Over-------------------------------\n");
			printf("\n");
			printf("----���ͷ����ͣ�---------------------UKB(aes_key)------------\n");
			BigInt rsa_aes_key(aes_key);//��aes_keyֵ��ʼ������		
			//cout << "���շ�B�Ĺ�ԿUKAΪ��" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
			BigInt rsa_aes_key_c = rsa_B.encryptByPu(rsa_aes_key);//���շ�B��ԿԿ���ܺ�����Ϊrsa_aes_key_m
			//BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
			cout << "���ܺ��aes_key:" << rsa_aes_key_c << endl;
			cout << endl;
			cout << endl;
			printf("----���ͷ����ͣ�-----------------------aes_key(Plain_hash)------------\n");
			uchar * aes_plain_hash = Cipher(&len3, plain_hash, (uchar *)aes_key.data());//���ܺ��plain_hash
			
			//printf("Encrypted plain_hash : ");
			for (int i = 0; i < len3; i++)
			{
				printf("%c", aes_plain_hash[i]);
			}
			printf("\n");
			cout << endl;
			cout << endl;
			printf("-------------------------���շ�B: RKB(aes_key_c)----------------------------\n");
			BigInt aes_key_B = rsa_B.decodeByPr(rsa_aes_key_c);
			cout << "���շ����ܺ��aes_key:" << aes_key_B << endl;
			cout << endl;
			string aes_key_B_str = aes_key_B.get_str(aes_key_B);//��BigInt����aes_keyת��Ϊstring���ͣ�string���ǿ��ת��Ϊuchar *
			printf("-------------------------���շ�B:aes_key(aes_plain_hash)---------------------\n");
			uchar * de_aes_plain_hash = InvCipher(&len3, aes_plain_hash, (uchar *)aes_key_B_str.data());//aes���ܵ�plain_hash
			printf("Decrypted plain_hash: ");
			for (int i = 0; i < len3; i++)
			{
				printf("%c", de_aes_plain_hash[i]);
			}
			printf("\n");       
			printf("-------------------------���շ�B:  ��aes_plain_hash��ΪM��EKA(hash)--------------------\n");//EK(hash)Ϊ�̶���64λ�ַ�
			string ss = (char*)de_aes_plain_hash;//��uchar ��(M)||(hash)ת��Ϊstring�����������������
			long long lens = ss.length();
			string ss_1 = ss.substr(lens-64, 64);//EKA(hash)Ϊ���64λ
			cout << "EKA(hash):" << ss_1 << endl;
			string ss_2 = ss.substr(0, lens - 64);
			cout << "plain_txt:" << ss_2 << endl;
			cout << endl;
			printf("-------------------------���շ�B:  UKA((EKA(hash))���hash--------------------\n");
			BigInt hash_final(ss_1);//���ܻ��(EKA(hash)Ϊss_1
			BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
			cout << "hash:" << hash_B_get << endl;
			string hash_B_1 = hash_B_get.get_str(hash_B_get);//��BigIntת��Ϊstring,Ϊ������hash�Ƚ���׼��
			cout << hash_B_1<<endl;
			printf("-------------------------���շ�B:  hash(plain_txt)���hash--------------------\n");
			if(cho1 == 1)//cho1=1��Ϊhash����ΪSHA;
			{
				cout << "hash����ΪSHA" << endl;
				string hash_B_2 = sha1(ss_2);//���ܻ������Ϊss_2
				Sleep(3000);//�ȴ�2s
				cout << "hash(plain_txt):" << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "����hashֵһ�£����ܹ��̽�����" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "����hashֵ��һ�£���������Bug��" << endl;
				}
			}
			if (cho1 == 2)//cho1=2��Ϊhash����ΪMD5;
			{
				cout << "hash����ΪMD5" << endl;
				string hash_B_2 = getMD5Code(ss_2);//���ܻ������Ϊss_2
				cout << "hash(plain_txt):"  << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "����hashֵһ�£����ܹ��̽�����" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "����hashֵ��һ�£���������Bug��" << endl;
				}
			}

		}
	}
	if (choice == 2)
	{
		//������Ҫ���ܵ��ļ�·��
		printf("��������Ҫ���ܵ��ı�·��������: \n");
		string input_file;
		cin >> input_file;
		int len3 = input_file.length();
		string output_file = input_file.substr(0, len3 - 4);
		output_file+="_cipher.txt";
		ifstream in;
		ofstream out;
		in.open(input_file);   //�����ļ�
		out.open(output_file); //��������ļ�
		char ch;
		long long count = 0;
		char* temp = new char[10000];   //�����ݴ����ݵ�����
		while (in&&in.get(ch)) {
			temp[count] = ch;
			count++;
		}
		in.close();//�����ļ���ر�
		char temp_1[10000];
		for (long long l = 0; l < count; l++)temp_1[l] = temp[l];
		cout << "temp:" << temp_1 << endl;
		string str1(temp_1);
		string hash = "";
		string str = str1;
		cout << str << endl;
		long long L1 = str.length()-1;
		if (L1% 16 != 0) {//�����Ĳ���16�ı�����Ҫ���㣻
			int n = str.length() % 16;
			cout << "����λ������16�ı�������Ҫ����λ��(���㲿����0���㣩��" << endl;
			for (int i = 0; i < 16 - n; i++)str += '0';
			cout << "����λ���������:" << endl;
			cout << str << endl;
		}
		//-------------ѡ��hash����������1��ʾSHA�㷨������2��ʾMD5�㷨-------------
		int cho1 = 0;//cho1=1��ʾSHA�㷨��cho1=2��ʾMD5�㷨
		while (1)
		{
			cout << "��ѡ��hash������1��ʾSHA�㷨��2��ʾMD5�㷨:  " << endl;
			cin >> cho1;
			cin.get();
			if (cho1 == 1 || cho1 == 2)break;
			else cout << "��ѡ����ȷ���㷨����!" << endl;
		}
		if (cho1 == 1)
		{
			cout << "ԭʼ���ģ�" << str << endl;
			cout << "Please wait for several seconds��" << endl;
			hash = sha1(str); //hashֵΪ160bit	
			Sleep(3000);//��Ҫsha1����ʱ���ӳ�
			cout << "SHA����������HASHֵ��" << hash << endl;

		}
		if (cho1 == 2)
		{
			//cout << "���ģ�" << str << endl;	
			hash = getMD5Code(str); //hashֵΪ128bit
			cout << "MD5������HASHֵ��" << hash << endl;
		}
		//-------------��hash����ǩ��-------------//
		BigInt rsa_plain(hash);//��hashֵ��ʼ������
		BigInt rsa_c = rsa_A.encryptByPr(rsa_plain);//˽ԿԿ���ܺ�����Ϊrsa_c
		//BigInt rsa_m = rsa_A.decodeByPu(rsa_c);//��Կ���ܺ�����Ϊ rsa_m
											   //cout << "���ͷ�A�Ĺ�ԿUKAΪ��" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
		cout << "RKA(hash(M)):" << rsa_c << endl;
		cout << endl;
		//	cout << "��֤ǩ����hash:" << rsa_m << endl;
		//	cout << endl;

		//��ǩ�����hash�������ĺ�
		cout << "��RKA(hash(M))�������ĺ�" << endl;
		string m_and_hash = str + rsa_c.get_str(rsa_c);
		cout << m_and_hash << endl;
		cout << endl;

		//-------------��ѡ��ѡ��ԳƼ����㷨��1��ʾDES�����㷨;2��ʾAES�㷨-------------
		int cho2 = 0;//cho2=1��ʾDES�����㷨��Ϊ2��ʾAES�㷨
		cout << "ѡ��ĶԳƼ����㷨��DES" << endl;
		//..........����Ԥ������BigInt ��Ϊstring����...........//
		string des_key = sym_key;//des��Կ16λ16��������
		string plain_hash = m_and_hash.data();//���ļ�hashֵ
		uint len5 = plain_hash.length();
		printf("Length of decrypted len3 = %d\n", len5);
		printf("-----------------------------DES Encryption Over-------------------------------\n");
		printf("\n");
		printf("----���ͷ�A����:---------------------UKB(des_key)------------\n");
		BigInt rsa_des_key(des_key);//��des_keyֵ��ʼ������		
										//cout << "���շ�B�Ĺ�ԿUKAΪ��" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
		BigInt rsa_des_key_c = rsa_B.encryptByPu(rsa_des_key);//���շ�B��ԿԿ���ܺ�����Ϊrsa_aes_key_m
			 //BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
		cout << "���ܺ��des_key:" << rsa_des_key_c << endl;
		cout << endl;
		cout << endl;
		printf("----���ͷ�A�� des_key(Plain_hash)д������ļ�----\n");
		string des_plain_hash = des_encryption(plain_hash, des_key);//���ܺ��plain_hash	
		out.write(des_plain_hash.data(), des_plain_hash.length());//��des_plain_hashд���ļ�
		out.close();
		cout << "des_key(Plain_hash):" << des_plain_hash << endl;
		cout << endl;
		cout << endl;
		printf("----���շ�B: ���ռ����ļ�(Ϊ�˷��㣬��A,B�ɷ�����ͬĿ¼��--------\n");
		BigInt des_key_B = rsa_B.decodeByPr(rsa_des_key_c);
		cout << "���շ����ܺ��des_key:" << des_key_B << endl;
		cout << endl;
		int  len4 = output_file.length();
		string de_crypt_file = output_file.substr(0, len4-10);
		de_crypt_file += "decipher.txt";
		ifstream in2;
		ofstream out2;
		in2.open(output_file);   //������ܺ���ļ�
		out2.open(de_crypt_file); //������ܺ���ļ�
		char ch1;
		long long count1 = 0;
			//cout << "output_file" << output_file << endl;
		char* temp1 =new char[10000];   //�����ݴ����ݵ�����
		while (in2&&in2.get(ch1))
		{
			temp1[count1] = ch1;
			count1++;
		}
			//cout << "count1" <<count1<< endl;
			//cout << "temp1:" << temp1 << endl;
		in.close();//�����ļ���ر�
		char temp2[10000];
		for (long long l = 0; l < count1+1; l++)temp2[l] = temp1[l];
		cout << "temp2:" << temp2 << endl;
			//string str1(temp2);
		des_plain_hash = string(temp2);//����ȡ�ļ�����Ϣ��ֵ��des_plain_hash
		string des_key_B_str = des_key_B.get_str(des_key_B);//��BigInt����des_keyת��Ϊstring����
		printf("------------���շ�B:---des_key(des_plain_hash)-----------\n");
		string de_des_plain_hash = des_decryption(des_plain_hash, des_key_B_str);//des���ܵ�plain_hash
		printf("Decrypted plain_hash: ");
		cout << de_des_plain_hash << endl;
		printf("\n");
		printf("-------------���շ�B:  ��des_plain_hash��ΪM��EKA(hash)--------------------\n");//EK(hash)Ϊ�̶���64λ�ַ�
		string ss = de_des_plain_hash;//��uchar ��(M)||(hash)ת��Ϊstring�����������������
		long long lens = ss.length();
		string ss_1 = ss.substr(lens - 64, 64);//EKA(hash)Ϊ���64λ
		cout << "EKA(hash):" << ss_1 << endl;
		string ss_2 = ss.substr(0, lens - 64);
		out2.write(ss_2.data(), ss_2.length());
		out2.close();
		cout << "plain_txt:" << ss_2 << endl;
		cout << endl;
		printf("-------------------------���շ�B:  UKA((EKA(hash))���hash--------------------\n");
		BigInt hash_final(ss_1);//���ܻ��(EKA(hash)Ϊss_1
		BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
		cout << "hash:" << hash_B_get << endl;
		string hash_B_1 = hash_B_get.get_str(hash_B_get);//��BigIntת��Ϊstring,Ϊ������hash�Ƚ���׼��
		//cout << hash_B_1 << endl;
		printf("-------------------------���շ�B:  hash(plain_txt)���hash--------------------\n");
		if (cho1 == 1)//cho1=1��Ϊhash����ΪSHA;
		{
			cout << "hash����ΪSHA" << endl;
			string hash_B_2 = sha1(ss_2);//���ܻ������Ϊss_2
			Sleep(3000);//��2��			
			cout << "hash(plain_txt):" << endl;
			cout << hash_B_2 << endl;
			if (hash_B_2 == hash_B_1)
			{
				cout << "����hashֵһ�£����ܽ��ܹ��̽�����" << endl;
			}
			if (hash_B_2 != hash_B_1) 
			{
				cout << "����hashֵ��һ�£���ע�����ķ�Χ�Ƿ�Ϊ{0123456789abcdef}��" << endl;
			}
		}
		if (cho1 == 2)//cho1=2��Ϊhash����ΪMD5;
		{
			cout << "hash����ΪMD5" << endl;
			string hash_B_2 = getMD5Code(ss_2);//���ܻ������Ϊss_2
			cout << "hash(plain_txt):" << endl;
			cout << hash_B_2 << endl;
			if (hash_B_2 == hash_B_1) 
			{
				cout << "����hashֵһ�£����ܽ��ܹ��̽�����" << endl;
			}
			if (hash_B_2 != hash_B_1) 
			{
				cout << "����hashֵ��һ�£���������Bug��" << endl;
			}
		}
	}
	if (choice == 3)
	{
		//locale::global(locale("chinese"));//��ȫ��������Ϊ����ϵͳĬ������
		printf("���ͷ�����ѡ�ļ����ͣ�txt,jpg,doc)���ܣ����շ����н��ܲ���֤���(����AES���� \n");
		printf("��������Ҫ���ܵ��ı�·��������: \n");
		string input_file;
		cin >> input_file;
		int len3 = input_file.length();
		string file_tax= input_file.substr(len3-4, 4);
		string output_file = input_file.substr(0, len3 - 4);
		output_file += "_cipher";
		output_file += file_tax;
		ifstream in;
		ofstream out;
		string aes_key = "0123456789fedcba";
		printf("-------------------------------AES Encryption Over-------------------------------\n");
		printf("\n");
		printf("--------���ͷ����ͣ�---------------------UKB(aes_key)------------\n");
		BigInt rsa_aes_key(aes_key);//��aes_keyֵ��ʼ������
		//cout << "���շ�B�Ĺ�ԿUKAΪ��" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
		BigInt rsa_aes_key_c = rsa_B.encryptByPu(rsa_aes_key);//���շ�B��ԿԿ���ܺ�����Ϊrsa_aes_key_m
		//BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
		cout << "--------���ܺ��aes_key--------:" << endl;
		cout<<rsa_aes_key_c << endl;
		cout << endl;
		cout << endl;
		printf("--------���ͷ�A�� des_key(Plain_hash)д������ļ�----\n");
		in.open(input_file, ios::binary);
		out.open(output_file, ios::binary);
		bitset<128>data;
		string aes_str;
		locale::global(locale("chinese"));//��ȫ��������Ϊ����ϵͳĬ������
		while (in.read((char *)&data, sizeof(data)))
		{
			char *tem = (char *)&data;
			string s1(tem);
			uint i = s1.length();
			//printf("%c", (char *)&data);
			uchar * aes_tem = Cipher(&i, (uchar *)tem, (uchar *)aes_key.data());
			out.write((char *)aes_tem, sizeof(data));
			data.reset();
		}
		cout << endl;
		in.close();
		out.close();
		//out.write((char *)aes_plain_hash,len3);//��des_plain_hashд���ļ�
		out.close();
		cout << "len3:" << len3 << endl;
		cout << endl;
		printf("--------���շ�B: RKB(aes_key_c)----------------------------\n");
		BigInt aes_key_B = rsa_B.decodeByPr(rsa_aes_key_c);
		cout << "���շ����ܺ��aes_key:" << aes_key_B << endl;
		cout << endl;
		string aes_key_B_str = aes_key_B.get_str(aes_key_B);//��BigInt����aes_keyת��Ϊstring���ͣ�string���ǿ��ת��Ϊuchar *
		printf("--------���շ�B: ��ȡ�����ļ�----------------------------\n");
		int  len4 = output_file.length();
		string de_crypt_file = output_file.substr(0, len4 - 10);
		de_crypt_file += "decipher";
		de_crypt_file += file_tax;
		ifstream in2;
		ofstream out2;
		in2.open(output_file, ios::binary);   //������ܺ���ļ�
		out2.open(de_crypt_file, ios::binary); //������ܺ���ļ�
		bitset<128> data1;
		locale::global(locale("chinese"));//��ȫ��������Ϊ����ϵͳĬ������
		while (in2.read((char *)&data1, sizeof(data1)))
		{
			char *tem = (char *)&data1;
			string s1(tem);
			uint i = s1.length();
			uchar * aes_tem = InvCipher(&i, (uchar *)tem, (uchar *)aes_key.data());
			
			out2.write((char *)aes_tem, sizeof(data));
			cout << (char *)aes_tem;
			data.reset();
		}
		cout << endl;
		in2.close();//�����ļ���ر�
		out2.close();
		cout << "decrypt finish!" << endl;
		cout << "���鵱ǰĿ¼�����ɵ�decipher�ļ���" << endl;
	}
	
	system("pause");
	return 0;
}