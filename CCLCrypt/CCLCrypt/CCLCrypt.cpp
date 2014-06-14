/*
 *  AES Crypt for windows and linux
 *  
 *     Sunzhimin <zhimins#gmail.com>
 *     http://www.anbei.cc
 *     这是自由软件，遵循LPGL协议，您可以自由修改、使用、分发，但修改部分请开源。
 *	   This a free software under LGPL license.
 */
//#include "stdafx.h"
#include <stdio.h>
#include <time.h>
#include "base64.h"
#include "CCLCrypt.h"
#include <string>
#ifndef WIN32
#include <unistd.h> // getopt
#include <iconv.h> // iconv stuff
#include <langinfo.h> // nl_langinfo
#include <errno.h> // errno
#include <stdlib.h>
#else
#include <windows.h>
#include <Wincrypt.h>
#pragma comment(lib,"crypt32.lib")
#endif
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
	int iRet=0;
	in=fopen(infilename,"rb");
	if(in == NULL)
		return -1;
	out =fopen(outfilename,"wb+");
	if(out==NULL)
	{
		fclose(in);
		return -1;
	}

	iRet=encrypt_stream(in,out,passwd,passwdlen,aheader);
	fclose(in);
	fclose(out);
	return iRet;
}
CCLCRYPT_API int CCLDecryptFile(const char *infilename,const char* outfilename,unsigned char * passwd,int passwdlen,aescrypt_hdr *aheader)
{
	FILE *in,*out;
	int iRet=0;
	in=fopen(infilename,"rb");
	if(in == NULL)
		return -1;
	out =fopen(outfilename,"wb+");
	if(out==NULL)
	{
		fclose(in);
		return -1;
	}

	iRet=decrypt_stream(in,out,passwd,passwdlen,aheader);
	fclose(in);
	fclose(out);
	return iRet;
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
#define MAX_PASSWD_BUF 30
#define MAX_PASSWD_LEN 30
CCLCRYPT_API std::string getpasswd(int length)
{


	const char pwchars[] =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z'
    };

    FILE *randfp;
    unsigned char pwtemp[MAX_PASSWD_BUF];
  
    int i;
   
    
    if ((length <= 0) || (length > MAX_PASSWD_LEN))
    {
        fprintf(stderr, "Invalid password length specified.\n");
        return "";
    }

  
#ifdef WIN32
	HCRYPTPROV                  hProv;
	if(!CryptAcquireContext( &hProv,NULL,NULL, PROV_RSA_FULL, 0))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            // No default container was found. Attempt to create it.
            if(!CryptAcquireContext(&hProv,NULL,NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
               
            {
               perror("CryptAcquireContext error");
			   return "";
            }
           
        }
        
    }
	 if (!CryptGenRandom(hProv,MAX_PASSWD_BUF,(BYTE *) pwtemp))
	 {
		 return "";
	 }
#else
	  /* Open the device to read random octets */
    if ((randfp = fopen("/dev/urandom", "r")) == NULL)
    {
        perror("Error open /dev/urandom:");
        return  "";
    }
    /* Read random octets */
	int n;
    if ((n = fread((char*)pwtemp, 1, MAX_PASSWD_BUF, randfp)) != length)
    {
        fprintf(stderr, "Error: Couldn't read from /dev/urandom\n");
        fclose(randfp);
        return  "";
    }
    fclose(randfp);
#endif
    /* Now ensure each octet is uses the defined character set */
   /* for(i = 0, p = pwtemp; i < length; i++, p++)
    {
        *p = pwchars[((int)(*p)) % 62];
    }
	strncpy((char*)password,(char*)pwtemp,length);
	*/
	string sPass;
	for(i=0;i<length;i++)
	{
		int r=(int)(*(pwtemp+i))%62;
		sPass+= pwchars[r];
	}
#ifdef WIN32
	CryptReleaseContext(
        hProv, 
        0);
#endif
    return sPass;
}


// 这是已导出类的构造函数。
// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 CCLCrypt.h
CCCLCrypt::CCCLCrypt()
{
	return;
}
