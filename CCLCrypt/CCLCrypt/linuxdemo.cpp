// demo.cpp : 定义控制台应用程序的入口点。
//

#include "CCLCrypt.h"
#include <string.h>

#include <stdio.h>
using namespace std;
int main(int argc, char* argv[])
{
	unsigned char passwd[100]={0};
	aescrypt_hdr ah;
	ah.bifzip=(unsigned char)0x1;
	sprintf((char*)passwd,"hello123");
	CCLCryptFile("x.tar","x.tar.crp",passwd,8,ah);
	printf("decrypt\n");
	//return 0;
	CCLDecryptFile("x.tar.crp","x2.tar",passwd,8,&ah);
	if(ah.bifzip==0x1)
		printf("bziped\n");
	else
		printf("not ziped\n");
	unsigned char src[10]="CloudLock";
	string sCryptPass=CCLCryptStr(src,10,passwd,9);
	printf("cryptpass[%s]\n",sCryptPass.c_str());
	string sSrcPass=CCLDEcryptStr(sCryptPass,passwd,9);
	printf("src pass[%s]\n",sSrcPass.c_str());
	getchar();
	return 0;
}

