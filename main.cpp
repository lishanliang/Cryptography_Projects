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
	//-------------发送方A产生公钥和私钥，接收方B产生公钥和私钥-------------
	cout << "Please wait for generating UKA and UKB" << endl;
	RSA rsa_A,rsa_B;
	rsa_A.init(128);//N=256;
	Sleep(1000);
	rsa_B.init(128);//N=256;
	cout << "发送方A的公钥UKA为：" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
	cout << "发送方B的公钥UKB为：" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;

	const unsigned int str_len = 16;
	unsigned char sym_key1[str_len + 1] = {};
	generateStr(sym_key1, str_len);
	string sym_key((char *)sym_key1);
	cout << "随机生成的对称密钥：" << sym_key << endl;
	/*选择操作类型：输入1为字符串加密；输入2为为文件加密；*/
	int choice=0;//choice=1为字符串加密；choice=2为为文件加密
	while(1)
	{
		printf("请选择操作类型：\n");
		printf("输入1表示对连续字符串(所有算法可选):签名->加密->解密->验证hash; \n");
		printf("输入2表示对文本文件内字符(对称算法：DES）:签名->加密->解密->验证hash; \n");
		printf("输入3表示对任意文件(对称算法：AES）:加密->解密->验证结果。 \n");
		cin >> choice;
		cin.get();
		if (choice == 1 || choice == 2||choice==3)break;
		else printf("请选择正确的操作类型!\n");
	}
	//----------对字符串加密-------------
	if (choice == 1)
	{
		//输入需要加密的字符串
		printf("请输入需要加密的字符串: \n");
		string str1 = "";
		string hash = "";
		getline(cin, str1);
		string str = str1;
		if (str.length() % 16 != 0) {//若明文不是16的倍数，要补足；
			int n = str.length() % 16;
			cout << "明文位数不是16的倍数，需要补足位数(不足部分由0补足）！" << endl;
			for (int i = 0; i < 16 - n; i++)str += '0';
			cout << "补足位数后的明文:" << endl;
			cout << str << endl;
		}
		//-------------选择hash函数：输入1表示SHA算法；输入2表示MD5算法-------------
		int cho1 = 0;//cho1=1表示SHA算法；cho1=2表示MD5算法
		while (1)
		{
			cout<<"请选择hash函数：1表示SHA算法；2表示MD5算法:  "<<endl;
			cin >> cho1;
			cin.get();
			if (cho1 == 1 || cho1 == 2)break;
			else cout << "请选择正确的算法类型!" << endl;
		}
		if (cho1 == 1)
		{
			cout << "原始明文：" << str << endl;
			cout << "Please wait for several seconds：" << endl;
			hash = sha1(str); //hash值为160bit	
			Sleep(3000);//需要sha1处理时间延迟
			cout << "SHA函数运算后的HASH值：" << hash<< endl;

		}
		if (cho1 == 2)
		{
			//cout << "明文：" << str << endl;	
			hash = getMD5Code(str); //hash值为128bit
			cout << "MD5运算后的HASH值：" << hash << endl;
		}
		//-------------发送方对hash进行加密-------------//
		BigInt rsa_plain(hash);//用hash值初始化大数
		BigInt rsa_c = rsa_A.encryptByPr(rsa_plain);//私钥钥加密后数据为rsa_c
		BigInt rsa_m = rsa_A.decodeByPu(rsa_c);//公钥解密后数据为 rsa_m
		//cout << "发送方A的公钥UKA为：" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
		cout << "签名后的hash:" << rsa_c << endl;
		cout << endl;
	//	cout << "验证签名的hash:" << rsa_m << endl;
	//	cout << endl;

		//将签名后的hash加在明文后
		cout << "将签名后的hash加在明文后输出："<<endl;
		string m_and_hash = str + rsa_c.get_str(rsa_c);
		cout << m_and_hash << endl;
		cout << endl;

		//-------------请选择选择对称加密算法：1表示DES加密算法;2表示AES算法-------------
		int cho2 = 0;//cho2=1表示DES加密算法，为2表示AES算法
		while (1)
		{
			cout << "请选择对称加密算法：1表示DES算法；2表示AES算法:  " << endl;
			cin >> cho2;
			cin.get();
			if (cho2 == 1 || cho2 == 2)break;
			else cout << "请选择正确的算法类型!" << endl;;
		}
		if (cho2 == 1)
		{
			cout << "选择的对称加密算法：DES" << endl;
			//..........数据预处理，把BigInt 变为string类型...........//
			string des_key = sym_key;//des密钥16位16进制数据
			string plain_hash =m_and_hash.data();//明文加hash值
			uint len3 = plain_hash.length();
			printf("Length of decrypted len3 = %d\n", len3);
			printf("-----------------------------DES Encryption Over-------------------------------\n");
			printf("\n");
			printf("----发送方发送：---------------------UKB(des_key)------------\n");
			BigInt rsa_des_key(des_key);//用des_key值初始化大数		
										//cout << "接收方B的公钥UKA为：" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
			BigInt rsa_des_key_c = rsa_B.encryptByPu(rsa_des_key);//接收方B公钥钥加密后数据为rsa_des_key_m
																  //BigInt rsa_des_key_m = rsa_B.decodeByPr(rsa_des_key_c);//
			cout << "加密后的des_key:" << rsa_des_key_c << endl;
			cout << endl;
			cout << endl;
			printf("----发送方发送：-----------------------des_key(Plain_hash)------------\n");
			string des_plain_hash = des_encryption(plain_hash, des_key);;//加密后的plain_hash																					
			cout << "des_key(Plain_hash):" << des_plain_hash << endl;
			cout << endl;
			cout << endl;
			printf("-------------------------接收方B:   RKB(UKB(des_key))----------------------------\n");
			BigInt des_key_B = rsa_B.decodeByPr(rsa_des_key_c);
			cout << "接收方解密后的des_key:" << des_key_B << endl;
			cout << endl;
			string des_key_B_str = des_key_B.get_str(des_key_B);//将BigInt类型des_key转化为string类型
			printf("-------------------------接收方B:   des_key(des_plain_hash)---------------------\n");
			string de_des_plain_hash = des_decryption(des_plain_hash, des_key_B_str);//des解密的plain_hash
			printf("Decrypted plain_hash: ");
			cout << de_des_plain_hash << endl;
			printf("\n");
			printf("-------------------------接收方B:  将des_plain_hash分为M和EKA(hash)--------------------\n");//EK(hash)为固定后64位字符
			string ss = de_des_plain_hash;//将uchar 的(M)||(hash)转化为string，方便接下来操作；
			long long lens = ss.length();
			string ss_1 = ss.substr(lens - 64, 64);//EKA(hash)为最后64位
			cout << "EKA(hash):" << ss_1 << endl;
			string ss_2 = ss.substr(0, lens - 64);
			cout << "plain_txt:" << ss_2 << endl;
			cout << endl;
			printf("-------------------------接收方B:  UKA((EKA(hash))获得hash--------------------\n");
			BigInt hash_final(ss_1);//解密获得(EKA(hash)为ss_1
			BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
			cout << "hash:" << hash_B_get << endl;
			string hash_B_1 = hash_B_get.get_str(hash_B_get);//将BigInt转化为string,为与明文hash比较做准备
			cout << hash_B_1 << endl;
			printf("-------------------------接收方B:  hash(plain_txt)获得hash--------------------\n");
			if (cho1 == 1)//cho1=1，为hash函数为SHA;
			{
				cout << "hash函数为SHA" << endl;
				string hash_B_2 = sha1(ss_2);//解密获得明文为ss_2
				Sleep(3000);//等2秒			
				cout << "hash(plain_txt):" << endl;
				cout<<hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "两个hash值一致，加密过程结束！" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "两个hash值不一致，还得再找Bug！" << endl;
				}
			}
			if (cho1 == 2)//cho1=2，为hash函数为MD5;
			{
				cout << "hash函数为MD5" << endl;
				string hash_B_2 = getMD5Code(ss_2);//解密获得明文为ss_2
				cout << "hash(plain_txt):" << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "两个hash值一致，加密过程结束！" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "两个hash值不一致，还得再找Bug！" << endl;
				}
			}
		}
		if (cho2 == 2)
		{
			cout << "选择的对称加密算法：AES" << endl;
			//..........数据预处理，把BigInt 变为uchar类型...........//
		    char* temp;
			temp = (char *)m_and_hash.data();//明文加hash值
			uchar * plain_hash;
			plain_hash = reinterpret_cast<uchar *>(temp);
			//cout << "plain_hash:" << plain_hash << endl;

			//..........对称加密过程：分别加密plain_hash 和公钥（UKa_e，UKa_N)........../
			string aes_key = sym_key;
			uint len3 = strlen((const char*)plain_hash)+1;
			printf("Length of decrypted len3 = %d\n", len3);
			printf("-----------------------------AES Encryption Over-------------------------------\n");
			printf("\n");
			printf("----发送方发送：---------------------UKB(aes_key)------------\n");
			BigInt rsa_aes_key(aes_key);//用aes_key值初始化大数		
			//cout << "接收方B的公钥UKA为：" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
			BigInt rsa_aes_key_c = rsa_B.encryptByPu(rsa_aes_key);//接收方B公钥钥加密后数据为rsa_aes_key_m
			//BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
			cout << "加密后的aes_key:" << rsa_aes_key_c << endl;
			cout << endl;
			cout << endl;
			printf("----发送方发送：-----------------------aes_key(Plain_hash)------------\n");
			uchar * aes_plain_hash = Cipher(&len3, plain_hash, (uchar *)aes_key.data());//加密后的plain_hash
			
			//printf("Encrypted plain_hash : ");
			for (int i = 0; i < len3; i++)
			{
				printf("%c", aes_plain_hash[i]);
			}
			printf("\n");
			cout << endl;
			cout << endl;
			printf("-------------------------接收方B: RKB(aes_key_c)----------------------------\n");
			BigInt aes_key_B = rsa_B.decodeByPr(rsa_aes_key_c);
			cout << "接收方解密后的aes_key:" << aes_key_B << endl;
			cout << endl;
			string aes_key_B_str = aes_key_B.get_str(aes_key_B);//将BigInt类型aes_key转化为string类型，string类可强制转化为uchar *
			printf("-------------------------接收方B:aes_key(aes_plain_hash)---------------------\n");
			uchar * de_aes_plain_hash = InvCipher(&len3, aes_plain_hash, (uchar *)aes_key_B_str.data());//aes解密的plain_hash
			printf("Decrypted plain_hash: ");
			for (int i = 0; i < len3; i++)
			{
				printf("%c", de_aes_plain_hash[i]);
			}
			printf("\n");       
			printf("-------------------------接收方B:  将aes_plain_hash分为M和EKA(hash)--------------------\n");//EK(hash)为固定后64位字符
			string ss = (char*)de_aes_plain_hash;//将uchar 的(M)||(hash)转化为string，方便接下来操作；
			long long lens = ss.length();
			string ss_1 = ss.substr(lens-64, 64);//EKA(hash)为最后64位
			cout << "EKA(hash):" << ss_1 << endl;
			string ss_2 = ss.substr(0, lens - 64);
			cout << "plain_txt:" << ss_2 << endl;
			cout << endl;
			printf("-------------------------接收方B:  UKA((EKA(hash))获得hash--------------------\n");
			BigInt hash_final(ss_1);//解密获得(EKA(hash)为ss_1
			BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
			cout << "hash:" << hash_B_get << endl;
			string hash_B_1 = hash_B_get.get_str(hash_B_get);//将BigInt转化为string,为与明文hash比较做准备
			cout << hash_B_1<<endl;
			printf("-------------------------接收方B:  hash(plain_txt)获得hash--------------------\n");
			if(cho1 == 1)//cho1=1，为hash函数为SHA;
			{
				cout << "hash函数为SHA" << endl;
				string hash_B_2 = sha1(ss_2);//解密获得明文为ss_2
				Sleep(3000);//等待2s
				cout << "hash(plain_txt):" << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "两个hash值一致，加密过程结束！" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "两个hash值不一致，还得再找Bug！" << endl;
				}
			}
			if (cho1 == 2)//cho1=2，为hash函数为MD5;
			{
				cout << "hash函数为MD5" << endl;
				string hash_B_2 = getMD5Code(ss_2);//解密获得明文为ss_2
				cout << "hash(plain_txt):"  << endl;
				cout << hash_B_2 << endl;
				if (hash_B_2 == hash_B_1) {
					cout << "两个hash值一致，加密过程结束！" << endl;
				}
				if (hash_B_2 != hash_B_1) {
					cout << "两个hash值不一致，还得再找Bug！" << endl;
				}
			}

		}
	}
	if (choice == 2)
	{
		//输入需要加密的文件路径
		printf("请输入需要加密的文本路径和名称: \n");
		string input_file;
		cin >> input_file;
		int len3 = input_file.length();
		string output_file = input_file.substr(0, len3 - 4);
		output_file+="_cipher.txt";
		ifstream in;
		ofstream out;
		in.open(input_file);   //输入文件
		out.open(output_file); //输出加密文件
		char ch;
		long long count = 0;
		char* temp = new char[10000];   //用来暂存内容的数组
		while (in&&in.get(ch)) {
			temp[count] = ch;
			count++;
		}
		in.close();//读完文件后关闭
		char temp_1[10000];
		for (long long l = 0; l < count; l++)temp_1[l] = temp[l];
		cout << "temp:" << temp_1 << endl;
		string str1(temp_1);
		string hash = "";
		string str = str1;
		cout << str << endl;
		long long L1 = str.length()-1;
		if (L1% 16 != 0) {//若明文不是16的倍数，要补足；
			int n = str.length() % 16;
			cout << "明文位数不是16的倍数，需要补足位数(不足部分由0补足）！" << endl;
			for (int i = 0; i < 16 - n; i++)str += '0';
			cout << "补足位数后的明文:" << endl;
			cout << str << endl;
		}
		//-------------选择hash函数：输入1表示SHA算法；输入2表示MD5算法-------------
		int cho1 = 0;//cho1=1表示SHA算法；cho1=2表示MD5算法
		while (1)
		{
			cout << "请选择hash函数：1表示SHA算法；2表示MD5算法:  " << endl;
			cin >> cho1;
			cin.get();
			if (cho1 == 1 || cho1 == 2)break;
			else cout << "请选择正确的算法类型!" << endl;
		}
		if (cho1 == 1)
		{
			cout << "原始明文：" << str << endl;
			cout << "Please wait for several seconds：" << endl;
			hash = sha1(str); //hash值为160bit	
			Sleep(3000);//需要sha1处理时间延迟
			cout << "SHA函数运算后的HASH值：" << hash << endl;

		}
		if (cho1 == 2)
		{
			//cout << "明文：" << str << endl;	
			hash = getMD5Code(str); //hash值为128bit
			cout << "MD5运算后的HASH值：" << hash << endl;
		}
		//-------------对hash进行签名-------------//
		BigInt rsa_plain(hash);//用hash值初始化大数
		BigInt rsa_c = rsa_A.encryptByPr(rsa_plain);//私钥钥加密后数据为rsa_c
		//BigInt rsa_m = rsa_A.decodeByPu(rsa_c);//公钥解密后数据为 rsa_m
											   //cout << "发送方A的公钥UKA为：" << '(' << rsa_A.e << ',' << rsa_A.N << ')' << endl;
		cout << "RKA(hash(M)):" << rsa_c << endl;
		cout << endl;
		//	cout << "验证签名的hash:" << rsa_m << endl;
		//	cout << endl;

		//将签名后的hash加在明文后
		cout << "将RKA(hash(M))加在明文后：" << endl;
		string m_and_hash = str + rsa_c.get_str(rsa_c);
		cout << m_and_hash << endl;
		cout << endl;

		//-------------请选择选择对称加密算法：1表示DES加密算法;2表示AES算法-------------
		int cho2 = 0;//cho2=1表示DES加密算法，为2表示AES算法
		cout << "选择的对称加密算法：DES" << endl;
		//..........数据预处理，把BigInt 变为string类型...........//
		string des_key = sym_key;//des密钥16位16进制数据
		string plain_hash = m_and_hash.data();//明文加hash值
		uint len5 = plain_hash.length();
		printf("Length of decrypted len3 = %d\n", len5);
		printf("-----------------------------DES Encryption Over-------------------------------\n");
		printf("\n");
		printf("----发送方A发送:---------------------UKB(des_key)------------\n");
		BigInt rsa_des_key(des_key);//用des_key值初始化大数		
										//cout << "接收方B的公钥UKA为：" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
		BigInt rsa_des_key_c = rsa_B.encryptByPu(rsa_des_key);//接收方B公钥钥加密后数据为rsa_aes_key_m
			 //BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
		cout << "加密后的des_key:" << rsa_des_key_c << endl;
		cout << endl;
		cout << endl;
		printf("----发送方A将 des_key(Plain_hash)写入加密文件----\n");
		string des_plain_hash = des_encryption(plain_hash, des_key);//加密后的plain_hash	
		out.write(des_plain_hash.data(), des_plain_hash.length());//将des_plain_hash写入文件
		out.close();
		cout << "des_key(Plain_hash):" << des_plain_hash << endl;
		cout << endl;
		cout << endl;
		printf("----接收方B: 接收加密文件(为了方便，设A,B可访问相同目录）--------\n");
		BigInt des_key_B = rsa_B.decodeByPr(rsa_des_key_c);
		cout << "接收方解密后的des_key:" << des_key_B << endl;
		cout << endl;
		int  len4 = output_file.length();
		string de_crypt_file = output_file.substr(0, len4-10);
		de_crypt_file += "decipher.txt";
		ifstream in2;
		ofstream out2;
		in2.open(output_file);   //输入加密后的文件
		out2.open(de_crypt_file); //输出解密后的文件
		char ch1;
		long long count1 = 0;
			//cout << "output_file" << output_file << endl;
		char* temp1 =new char[10000];   //用来暂存内容的数组
		while (in2&&in2.get(ch1))
		{
			temp1[count1] = ch1;
			count1++;
		}
			//cout << "count1" <<count1<< endl;
			//cout << "temp1:" << temp1 << endl;
		in.close();//读完文件后关闭
		char temp2[10000];
		for (long long l = 0; l < count1+1; l++)temp2[l] = temp1[l];
		cout << "temp2:" << temp2 << endl;
			//string str1(temp2);
		des_plain_hash = string(temp2);//将读取的加密信息赋值给des_plain_hash
		string des_key_B_str = des_key_B.get_str(des_key_B);//将BigInt类型des_key转化为string类型
		printf("------------接收方B:---des_key(des_plain_hash)-----------\n");
		string de_des_plain_hash = des_decryption(des_plain_hash, des_key_B_str);//des解密的plain_hash
		printf("Decrypted plain_hash: ");
		cout << de_des_plain_hash << endl;
		printf("\n");
		printf("-------------接收方B:  将des_plain_hash分为M和EKA(hash)--------------------\n");//EK(hash)为固定后64位字符
		string ss = de_des_plain_hash;//将uchar 的(M)||(hash)转化为string，方便接下来操作；
		long long lens = ss.length();
		string ss_1 = ss.substr(lens - 64, 64);//EKA(hash)为最后64位
		cout << "EKA(hash):" << ss_1 << endl;
		string ss_2 = ss.substr(0, lens - 64);
		out2.write(ss_2.data(), ss_2.length());
		out2.close();
		cout << "plain_txt:" << ss_2 << endl;
		cout << endl;
		printf("-------------------------接收方B:  UKA((EKA(hash))获得hash--------------------\n");
		BigInt hash_final(ss_1);//解密获得(EKA(hash)为ss_1
		BigInt hash_B_get = rsa_A.decodeByPu(hash_final);
		cout << "hash:" << hash_B_get << endl;
		string hash_B_1 = hash_B_get.get_str(hash_B_get);//将BigInt转化为string,为与明文hash比较做准备
		//cout << hash_B_1 << endl;
		printf("-------------------------接收方B:  hash(plain_txt)获得hash--------------------\n");
		if (cho1 == 1)//cho1=1，为hash函数为SHA;
		{
			cout << "hash函数为SHA" << endl;
			string hash_B_2 = sha1(ss_2);//解密获得明文为ss_2
			Sleep(3000);//等2秒			
			cout << "hash(plain_txt):" << endl;
			cout << hash_B_2 << endl;
			if (hash_B_2 == hash_B_1)
			{
				cout << "两个hash值一致，加密解密过程结束！" << endl;
			}
			if (hash_B_2 != hash_B_1) 
			{
				cout << "两个hash值不一致，请注意明文范围是否为{0123456789abcdef}！" << endl;
			}
		}
		if (cho1 == 2)//cho1=2，为hash函数为MD5;
		{
			cout << "hash函数为MD5" << endl;
			string hash_B_2 = getMD5Code(ss_2);//解密获得明文为ss_2
			cout << "hash(plain_txt):" << endl;
			cout << hash_B_2 << endl;
			if (hash_B_2 == hash_B_1) 
			{
				cout << "两个hash值一致，加密解密过程结束！" << endl;
			}
			if (hash_B_2 != hash_B_1) 
			{
				cout << "两个hash值不一致，还得再找Bug！" << endl;
			}
		}
	}
	if (choice == 3)
	{
		//locale::global(locale("chinese"));//将全局区域设为操作系统默认区域
		printf("发送方对任选文件类型（txt,jpg,doc)加密；接收方进行解密并验证结果(基于AES）。 \n");
		printf("请输入需要加密的文本路径和名称: \n");
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
		printf("--------发送方发送：---------------------UKB(aes_key)------------\n");
		BigInt rsa_aes_key(aes_key);//用aes_key值初始化大数
		//cout << "接收方B的公钥UKA为：" << '(' << rsa_B.e << ',' << rsa_B.N << ')' << endl;
		BigInt rsa_aes_key_c = rsa_B.encryptByPu(rsa_aes_key);//接收方B公钥钥加密后数据为rsa_aes_key_m
		//BigInt rsa_aes_key_m = rsa_B.decodeByPr(rsa_aes_key_c);//
		cout << "--------加密后的aes_key--------:" << endl;
		cout<<rsa_aes_key_c << endl;
		cout << endl;
		cout << endl;
		printf("--------发送方A将 des_key(Plain_hash)写入加密文件----\n");
		in.open(input_file, ios::binary);
		out.open(output_file, ios::binary);
		bitset<128>data;
		string aes_str;
		locale::global(locale("chinese"));//将全局区域设为操作系统默认区域
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
		//out.write((char *)aes_plain_hash,len3);//将des_plain_hash写入文件
		out.close();
		cout << "len3:" << len3 << endl;
		cout << endl;
		printf("--------接收方B: RKB(aes_key_c)----------------------------\n");
		BigInt aes_key_B = rsa_B.decodeByPr(rsa_aes_key_c);
		cout << "接收方解密后的aes_key:" << aes_key_B << endl;
		cout << endl;
		string aes_key_B_str = aes_key_B.get_str(aes_key_B);//将BigInt类型aes_key转化为string类型，string类可强制转化为uchar *
		printf("--------接收方B: 读取加密文件----------------------------\n");
		int  len4 = output_file.length();
		string de_crypt_file = output_file.substr(0, len4 - 10);
		de_crypt_file += "decipher";
		de_crypt_file += file_tax;
		ifstream in2;
		ofstream out2;
		in2.open(output_file, ios::binary);   //输入加密后的文件
		out2.open(de_crypt_file, ios::binary); //输出解密后的文件
		bitset<128> data1;
		locale::global(locale("chinese"));//将全局区域设为操作系统默认区域
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
		in2.close();//读完文件后关闭
		out2.close();
		cout << "decrypt finish!" << endl;
		cout << "请检查当前目录下生成的decipher文件。" << endl;
	}
	
	system("pause");
	return 0;
}