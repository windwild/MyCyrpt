#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>




#define BLOCK_SIZE 8
#define BUFFER_SIZE 1024
#define CERT 1000
#define LPRI 1001
#define SPUB 1002
#define SPRI 1003
#define LP 1004
#define SP 1005
#define RSA_SIZE 128
#define BUFSIZE 1024
#define SIGLEN 128


unsigned int getfilesize(char* filepath);
int sha256_file(char *path, unsigned char* outputBuffer);
int certfile(char* path,char *destination, char* pempath, unsigned char* signiture);
int rsa_encrypt(unsigned char* source,int inputsize, unsigned char* done, char* pempath);
int rsa_decrypt(unsigned char* source,int outputsize, unsigned char* done, char* pempath);
int aes_file(char* filepath, char* destination, unsigned char* key);
int aes_encrypt(char *filepath, char *destination, unsigned char *key);
int aes_decrypt(char *filepath, char *destination, unsigned char *key);

static const char *optString = "edf:";

static const struct option longOpts[] = {
    { "cert", required_argument, NULL, '1' },
    { "lpri", required_argument, NULL, '2' },
    { "spub", required_argument, NULL, '3' },
    { "spri", required_argument, NULL, '4' },
    { "lp", required_argument, NULL, '5' },
    { "sp", required_argument, NULL, '6' },
    { NULL, no_argument, NULL, 0 }
};
