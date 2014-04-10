// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� CCLCRYPT_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// CCLCRYPT_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#pragma once
#ifdef WIN32
#ifdef CCLCRYPT_EXPORTS
#define CCLCRYPT_API __declspec(dllexport)
#else
#define CCLCRYPT_API __declspec(dllimport)
#endif
#else
#define CCLCRYPT_API
#endif
#include <string>
#include "aescrypt.h"
// �����Ǵ� CCLCrypt.dll ������
class CCLCRYPT_API CCCLCrypt {
public:
	CCCLCrypt(void);
	// TODO: �ڴ�������ķ�����
};
/*
typedef struct
{
	char name[10];
	char 
}CryptHeader;
*/

CCLCRYPT_API int CCLCryptFile(const char *infilename,const char* outfilename,unsigned char * passwd,int passwdlen,aescrypt_hdr &aheader);
CCLCRYPT_API int CCLDecryptFile(const char *infilename,const char* outfilename,unsigned char * passwd,int passwdlen,aescrypt_hdr *aheader);
CCLCRYPT_API std::string CCLCryptStr(const unsigned char *src,int srclen,unsigned char * passwd,int passwdlen);
CCLCRYPT_API std::string CCLDEcryptStr(std::string src,unsigned char * passwd,int passwdlen);
CCLCRYPT_API int compressFile(const char *sourcefile, const char *destfile, int level);
CCLCRYPT_API int deCompressFile(const char *sourcefile, const char *destfile);
