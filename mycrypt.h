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
#include <arpa/inet.h>




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
#define SIGLEN 48


unsigned int getfilesize(char* filepath);
int sha256_file(char *path, unsigned char* outputBuffer);
int certfile(char* path, char* pempath, unsigned char* signature, char* passphrase);
int cert_verify(unsigned char* signature,char* destination, char* pempath, unsigned int filesize);
int rsa_encrypt(unsigned char *k,unsigned int filesize, unsigned char* done, char* pempath);
int rsa_decrypt(unsigned char* source,unsigned char *k, unsigned int *filesize,char* pempath, char* passphrase);
int aes_encrypt(char *filepath, char *destination, unsigned char *key,unsigned int filesize, unsigned char* signature);
int aes_decrypt(char *filepath, char *destination, unsigned char* key,unsigned int filesize, unsigned char* signature);
int encrypt_file(char* filepath, char* lpri, char* spub, char* passphrase);
int decrypt_file(char* filepath, char* cert, char* spri, char* passphrase);


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
