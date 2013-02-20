#include "mycrypt.h"

unsigned int getfilesize(char* filepath){
    struct stat st;
    if(stat(filepath,&st) == 0){
        return st.st_size;
    }
    return 0;
}

int sha256_file(char *path, unsigned char* outputBuffer){
    unsigned int filesize;
    char* filesize_str = (char*)malloc(256);
    filesize = getfilesize(path);
    sprintf(filesize_str, "%d", filesize);
    FILE *file = fopen(path, "rb");
    if(!file) return -1;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 1024;
    char *buffer = (char *)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return -1;
    SHA256_Update(&sha256, filesize_str, strlen(filesize_str));
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(outputBuffer, &sha256);


    SHA256_Init(&sha256);
    SHA256_Update(&sha256, outputBuffer, 32);
    SHA256_Final(outputBuffer, &sha256);

    fclose(file);
    free(buffer);
    return 0;
}

int certfile(char* path, char* pempath, unsigned char* signature, char* passphrase){
    FILE* fp;
    DSA* dsa;

    unsigned char* sign_string;
    unsigned int sig_len;
    unsigned char sha[32];

    SHA_CTX sha1;
    SHA1_Init(&sha1);
    const int bufSize = 1024;
    unsigned char *buffer = (unsigned char *)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return -1;

    FILE *file = fopen(path, "rb");
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA1_Update(&sha1, buffer, bytesRead);
    }
    SHA1_Final(sha, &sha1);
    fclose(file);

    if ((fp = fopen(pempath, "r")) == NULL) {
        fprintf(stderr, "Unable to open DSA private key file\n");
        return(-1);
    }
    OpenSSL_add_all_algorithms();
    dsa = PEM_read_DSAPrivateKey(fp, NULL, NULL, passphrase);
    if (dsa == NULL) {
        fprintf(stderr, "cannot read DSA private key.\n");
        return(-1);
    }
    fclose(fp);

    sig_len = SIGLEN;
    sign_string = (unsigned char*)calloc(sig_len, 1);   
    if (sign_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for sign_string\n");
        return(-1);
    }
    //DSAparams_print_fp(stdout, dsa);
    if (DSA_sign(0, sha, 20, signature, &sig_len, dsa) == 0) {
        fprintf(stderr, "Sign Error.\n");
        exit(-1);
    }
    free(buffer);

    return 0;
}


int cert_verify(unsigned char* signature,char* destination, char* pempath, unsigned int filesize){
    DSA* dsa;

    unsigned char sha[32];
    FILE *file = fopen(destination, "rb");
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    const int bufSize = 1024;
    char *buffer = (char *)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return -1;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA1_Update(&sha1, buffer, bytesRead);
    }
    SHA1_Final(sha, &sha1);
    fclose(file);

    FILE* fp;
    if ((fp = fopen(pempath, "r")) == NULL) {
        fprintf(stderr, "Unable to open RSA public key file\n");
        return(-1);
    }
    dsa = PEM_read_DSA_PUBKEY(fp, NULL, NULL, NULL);
    if (dsa == NULL) {
        fprintf(stderr, "cannot read DSA public key.\n");
        return(-1);
    }
    fclose(fp);


    int valid = DSA_verify(0, sha, 20, signature, SIGLEN, dsa);
    return valid;

}


int rsa_encrypt(unsigned char *k,unsigned int filesize, unsigned char* done,
 char* pempath){
    FILE* file;
    RSA* p_rsa;
    int encrypt_size;
    char filesize_str[8];
    unsigned char* source = (unsigned char*)calloc(RSA_SIZE,1);
    memcpy(source,k,32);

    BIGNUM* bn = BN_new();
    BN_init(bn);
    sprintf(filesize_str,"%d",filesize);
    BN_dec2bn (&bn, filesize_str);
    BN_bn2bin(bn,source + 36 - BN_num_bytes(bn));



    if((file=fopen(pempath,"r"))==NULL){
        printf("open key file error");
        return -1;    
    }

    if((p_rsa = PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL)) == NULL){
        printf("RSA public key error\n");
        return -1;
    }

    if((encrypt_size = RSA_public_encrypt(36,source,done,p_rsa,RSA_PKCS1_OAEP_PADDING)) < 0){
        printf("RSA encrypt error\n");
        return -1;
    }

    RSA_free(p_rsa);
    fclose(file);
    BN_free(bn);
    return encrypt_size;
}


int rsa_decrypt(unsigned char* source,unsigned char *k, unsigned int *filesize,
                char* pempath, char* passphrase){
    FILE* file;
    RSA *p_rsa;
    char * filesize_str;
    unsigned char* buffer;
    buffer = (unsigned char*)calloc(1,RSA_SIZE);
    memset(buffer,0,RSA_SIZE);
    if((file=fopen(pempath,"r"))==NULL){
        perror("open private key file error");
        return -1;
    }
    OpenSSL_add_all_algorithms();
    p_rsa = PEM_read_RSAPrivateKey(file,NULL,NULL,passphrase);

    if(p_rsa == NULL){
        printf("cannot read private key\n");
        return -1;
    }

    if(RSA_private_decrypt(RSA_SIZE,source,buffer,p_rsa,
        RSA_PKCS1_OAEP_PADDING) < 0){
        ERR_print_errors_fp(stdout);
        fprintf(stderr, "RSA decript error\n");
        return -1;
    }
    memcpy(k,buffer,32);
    BIGNUM* bn = BN_new();
    BN_bin2bn(buffer+32,4,bn);
    filesize_str = BN_bn2dec(bn);

    *filesize = atoi(filesize_str);
    RSA_free(p_rsa);
    fclose(file);
    BN_free(bn);
    return 0;
}


int aes_encrypt(char *filepath, char *destination, unsigned char *key,
                unsigned int filesize, unsigned char* signature){
    unsigned char input[512];
    unsigned char buffer[512];
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    int i,bytesRead;

    FILE* infile;
    FILE* outfile;

    infile = fopen(filepath,"rb");
    if(NULL == infile){
        fprintf(stderr, "cannot open infile\n");
        return -1;
    }

    outfile = fopen(destination,"ab");
    if(NULL == outfile){
        fprintf(stderr, "cannot open outfile\n");
        return -1;
    }
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 256, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }

    int block = ceil(1.0 * filesize / AES_BLOCK_SIZE);

    while(block > 1){
        bytesRead = fread(input, 1, AES_BLOCK_SIZE, infile);
        AES_cbc_encrypt(input, buffer, AES_BLOCK_SIZE, &aes, iv,
            AES_ENCRYPT);
        fwrite(buffer,1,AES_BLOCK_SIZE,outfile);
        --block;
    }

    bytesRead = fread(input, 1, AES_BLOCK_SIZE, infile);
    memcpy(input+bytesRead, signature, SIGLEN);

    for(i=0;i<4;++i){
        AES_cbc_encrypt(input+i*AES_BLOCK_SIZE, buffer, AES_BLOCK_SIZE,
                        &aes, iv, AES_ENCRYPT);
        fwrite(buffer,1,AES_BLOCK_SIZE,outfile);
    }
    
    fflush(outfile);
    fclose(infile);
    fclose(outfile);

    return 0;
}


int aes_decrypt(char *filepath, char *destination, unsigned char* key,
                unsigned int filesize, unsigned char* signature){
    unsigned char input[512];
    unsigned char buffer[512];
    unsigned char buffer2[512];
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    int i;
    FILE* infile;
    FILE* outfile;

    infile = fopen(filepath,"rb");
    if(infile == NULL){
        printf("input file open error\n");
        return -1;
    }
    fseek(infile,RSA_SIZE,SEEK_SET);

    outfile = fopen(destination,"wb");
    if(outfile == NULL){
        printf("output file open error\n");
        return -1;
    }

    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }

    if (AES_set_decrypt_key(key, 256, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }
    int block = ceil(1.0 * filesize / AES_BLOCK_SIZE);
    for(i=0;i<block-1;++i){
        fread(input, 1, AES_BLOCK_SIZE, infile);
        AES_cbc_encrypt(input, buffer, AES_BLOCK_SIZE, &aes, iv, AES_DECRYPT);
        fwrite(buffer,1,AES_BLOCK_SIZE,outfile);
    }
    fread(input, 1, AES_BLOCK_SIZE * 4, infile);
    for(i=0;i<4;++i){
        AES_cbc_encrypt(input+i*AES_BLOCK_SIZE, buffer2+i * AES_BLOCK_SIZE,
            AES_BLOCK_SIZE, &aes, iv, AES_DECRYPT);
    }
    fwrite(buffer2,1,(filesize-1)%AES_BLOCK_SIZE+1, outfile);
    memcpy(signature,buffer2+(filesize-1)%AES_BLOCK_SIZE + 1,48);

    fflush(outfile);
    fclose(infile);
    fclose(outfile);
    return 0;
}



int encrypt_file(char* filepath, char* lpri, char* spub, char* passphrase){
    unsigned char* buffer;
    buffer = (unsigned char*)calloc(1,BUFFER_SIZE);
    unsigned int filesize;
    unsigned char k[32];
    unsigned char signature[SIGLEN];


    char outpath[1024];
    sprintf(outpath, "%s.enc", filepath);
    FILE *outfile = fopen(outpath, "wb");
    if(!outfile){
        printf("Out File open error\n");
        return(NULL);
    }

    //Get file header K and filesize
    filesize = getfilesize(filepath);
    sha256_file(filepath, k);

    //Encrypt file header
    rsa_encrypt(k, filesize, buffer, spub);
    //write encrypted file header to file

    if(fwrite(buffer, RSA_SIZE, 1, outfile) == 0){
        printf("file write errror\n");
        fclose(outfile);
        return(NULL);
    }
    fflush(outfile);
    fclose(outfile);

    //calculate signature

    certfile(filepath, lpri, signature, passphrase);

    aes_encrypt(filepath, outpath, k, filesize, signature);

    free(buffer);
    return 0;
}

int decrypt_file(char* filepath, char* cert, char* spri, char* passphrase){
    FILE* file;
    unsigned char signature[SIGLEN];
    unsigned int filesize;
    unsigned char k[32];
    unsigned char *buffer;
    buffer = (unsigned char*)calloc(1,BUFFER_SIZE);

    char destination[512];
    sprintf(destination,"%s.txt",filepath);

    file = fopen(destination,"wb");
    fclose(file);


    if((file = fopen( filepath, "r")) == NULL){
        printf("encrypted file open error");
        return NULL;
    }
    fread(buffer, RSA_SIZE, 1, file);
    fclose(file);

    rsa_decrypt(buffer, k, &filesize, spri, passphrase);

    printf("filesize:%d\n", filesize);
    if(filesize > 0){
        aes_decrypt(filepath, destination, k, filesize, signature);
    }

    free(buffer);

    if(cert_verify(signature, destination, cert ,filesize) == 1 || filesize == 0){
        printf("signature verified seccessful!\n");
    }else{
        printf("signature verified failed!\n");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char filepath[1024];
    char lpri[1024];
    char spub[1024];
    char passphrase[1024];
    char cert[1024];
    char spri[1024];

    int opt = 0;
    int longIndex = 0;
    int mode = 0; // 1 decrypt, 2 encrypt
    opt = getopt_long_only( argc, argv, optString, longOpts, &longIndex );
    while( opt != -1 ) {
        switch( opt ) {
            case 'e':
                //printf("encrypt mode\n");
                if(mode != 0){
                    fprintf(stderr, "set mode error\n");
                    exit(-1);
                }
                mode = 2;
                break;
                
            case 'd':
                if(mode != 0){
                    fprintf(stderr, "set mode error\n");
                    exit(-1);
                }
                mode = 1;
                break;
                
            case 'f':
                strcpy(filepath, optarg);
                break;
                
            case '1':
                strcpy(cert, optarg);
                break;
                
            case '2':
                strcpy(lpri, optarg);
                break;

            case '3':
                strcpy(spub, optarg);
                break;

            case '4':
                strcpy(spri, optarg);
                break;

            case '5':
                strcpy(passphrase, optarg);
                break;

            case '6':
                //printf("sp:%s\n", optarg);
                strcpy(passphrase, optarg);
                break;

            case 0:     /* long option without a short arg */
                fprintf(stderr, "please input your option!\n");
                exit(-1);
                break;
                
            default:
                break;
        }
        
        opt = getopt_long_only( argc, argv, optString, longOpts, &longIndex );
    }
    if(mode == 1){
        decrypt_file(filepath,cert,spri,passphrase);
    }else{
        encrypt_file(filepath,lpri,spub,passphrase);
    }

    return 0;
}
