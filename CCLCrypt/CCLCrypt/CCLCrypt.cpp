// CCLCrypt.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdio.h>
#include <time.h>
#include "base64.h"
#include "CCLCrypt.h"
#include <string>

#ifndef WIN32

#include <string.h>

#endif
using namespace std;
extern "C"
{
int encrypt_stream(FILE *infp, FILE *outfp, unsigned char* passwd, int passlen,aescrypt_hdr aheader);
int decrypt_stream(FILE *infp, FILE *outfp, unsigned char* passwd, int passlen,aescrypt_hdr *aheader);


}
CCLCRYPT_API int CCLCryptFile(const char *infilename,const char* outfilename,unsigned char * passwd,int passwdlen,aescrypt_hdr &aheader)
{
	FILE *in,*out;
	in=fopen(infilename,"rb");
	if(in == NULL)
		return -1;
	out =fopen(outfilename,"wb+");
	if(out==NULL)
	{
		fclose(in);
		return -1;
	}

	encrypt_stream(in,out,passwd,passwdlen,aheader);
	fclose(in);
	fclose(out);
	return 0;
}
CCLCRYPT_API int CCLDecryptFile(const char *infilename,const char* outfilename,unsigned char * passwd,int passwdlen,aescrypt_hdr *aheader)
{
	FILE *in,*out;
	in=fopen(infilename,"rb");
	if(in == NULL)
		return -1;
	out =fopen(outfilename,"wb+");
	if(out==NULL)
	{
		fclose(in);
		return -1;
	}

	decrypt_stream(in,out,passwd,passwdlen,aheader);
	fclose(in);
	fclose(out);
	return 0;
}

CCLCRYPT_API std::string CCLCryptStr(const unsigned char *src,int srclen,unsigned char * passwd,int passwdlen)
{
	aes_context					aes_ctx;
    sha256_context              sha_ctx;
    sha256_t                    digest;
	unsigned char               buffer[32], buffer2[32];
	unsigned char               IV[16];
	
	
	//用于加密口令，不超过16个字符
	if(passwdlen>16)
		return "";
	//这个随机度不够，只能用于保证每次加密结果不同
	for(int i=0;i<8;i++)
	{
		srand(time(NULL));
		int irand=rand();
		memcpy(buffer2+i*4,&irand,4);
	}
	sha256_starts(  &sha_ctx);       
    sha256_update(  &sha_ctx,
                        buffer2,
                        32);
    sha256_finish(  &sha_ctx,
                        digest);
	memcpy(IV, digest, 16);
	memcpy(buffer2,IV,16);
	memset(digest, 0, 32);
    memcpy(digest, IV, 16);
	for(int i=0;i<1024;i++)
	{
		sha256_starts(  &sha_ctx);
        sha256_update(  &sha_ctx, digest, 32);
        sha256_update(  &sha_ctx,
                        passwd,
                        passwdlen);
        sha256_finish(  &sha_ctx,
                        digest);
	}
	aes_set_key(&aes_ctx, digest, 256);
	memset(buffer,0,32);
	memcpy(buffer,src,srclen);
	aes_encrypt(&aes_ctx, buffer, buffer);
	memcpy(buffer2+16,buffer,16);
	string sBase64=base64_encode(buffer2,32);

	return sBase64;
}
CCLCRYPT_API std::string CCLDEcryptStr(string src,unsigned char * passwd,int passwdlen)
{
	aes_context                 aes_ctx;
    sha256_context              sha_ctx;
    sha256_t                    digest;
    unsigned char               IV[16];
	string						sBaseDecode;
	
	unsigned char				buffer[32],buffer2[32];
	
	sBaseDecode=base64_decode(src);
	memcpy(buffer,(unsigned char*)sBaseDecode.c_str(),32);
	memcpy(IV,buffer,16);
	memset(digest, 0, 32);
    memcpy(digest, IV, 16);
	for(int i=0;i<1024;i++)
	{
		sha256_starts(  &sha_ctx);
        sha256_update(  &sha_ctx, digest, 32);
        sha256_update(  &sha_ctx,
                        passwd,
                        passwdlen);
        sha256_finish(  &sha_ctx,
                        digest);
	}
	aes_set_key(&aes_ctx, digest, 256);
	memcpy(buffer2,buffer+16,16);
	aes_decrypt(&aes_ctx, buffer2, buffer2);
	string sResult=(char*)buffer2;

	return sResult;
}
// 这是已导出类的构造函数。
// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 CCLCrypt.h
CCCLCrypt::CCCLCrypt()
{
	return;
}
