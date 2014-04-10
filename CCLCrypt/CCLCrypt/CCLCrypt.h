// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 CCLCRYPT_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// CCLCRYPT_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
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
// 此类是从 CCLCrypt.dll 导出的
class CCLCRYPT_API CCCLCrypt {
public:
	CCCLCrypt(void);
	// TODO: 在此添加您的方法。
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
