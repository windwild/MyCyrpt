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

    fclose(file);
    free(buffer);
    return 0;
}

int certfile(char* path, char* pempath, unsigned char* signiture, char* passphrase){
    FILE* fp;
    //FILE* outfile;
    EVP_MD_CTX evp_md_ctx;
    EVP_PKEY* priv_key; 

    unsigned char* sign_string;
    unsigned int sig_len;


    OpenSSL_add_all_algorithms();
    if ((fp = fopen(pempath, "r")) == NULL) {
        fprintf(stderr, "Unable to oepn private key file\n");
        return(-1);
    }
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, passphrase);
    if (priv_key == NULL) {
        fprintf(stderr, "cannot read private key.\n");
        return(-1);
    }
    fclose(fp);

    sig_len = SIGLEN;
    sign_string = (unsigned char*)calloc(sig_len, sizeof(unsigned char));   
    if (sign_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for sign_string\n");
        return(-1);
    }


    EVP_SignInit(&evp_md_ctx, EVP_sha1());
    char *buffer = (char *)malloc(BUFSIZE);
    int bytesRead = 0;
    if(!buffer) return -1;
    if ((fp = fopen(path, "rb")) == NULL) {
        fprintf(stderr, "Unable to oepn file\n");
        return(-1);
    }

    while((bytesRead = fread(buffer, 1, BUFSIZE, fp)))
    {
        EVP_SignUpdate(&evp_md_ctx, buffer, bytesRead);
    }
    if (EVP_SignFinal(&evp_md_ctx, signiture, &sig_len, priv_key) == 0) { 
        EVP_cleanup();
        fprintf(stderr, "Unable to sign\n");
        return(-1);
    }
    fclose(fp);
    // outfile = fopen(destination,"ab");

    // fwrite(signiture, 1, SIGLEN, outfile);

    // fflush(outfile);
    // fclose(outfile);
    free(buffer);

    return 0;
}


int cert_verify(unsigned char* signiture,char* destination, char* pempath, unsigned int filesize){
    FILE* fp;
    X509* cert;
    EVP_PKEY* pub_key;
    EVP_MD_CTX evp_md_ctx;

    OpenSSL_add_all_algorithms();

    if ((fp = fopen(pempath, "r")) == NULL) {           
        fprintf(stderr, "cannot open x509 cert file\n");
        exit(-1);                                         
    }
    if ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "cannot read cert file\n");
        exit(-1);
    } 
    if ((pub_key = X509_get_pubkey(cert)) == NULL) {
        fprintf(stderr, "cannot read x509's public key\n");
        exit(-1);                                         
    } 
    fclose(fp);

    if ((fp = fopen(destination, "rb")) == NULL) {           
        fprintf(stderr, "cannot read file\n");
        exit(-1);
    }

    EVP_VerifyInit(&evp_md_ctx, EVP_sha1());
    char *buffer = (char *)malloc(BUFSIZE);
    int bytesRead = 0;
    if(!buffer) return -1;

    while((bytesRead = fread(buffer, 1, BUFSIZE, fp)))
    {  
        EVP_VerifyUpdate(&evp_md_ctx, buffer, bytesRead);
    }
    fclose(fp);

    int is_valid_signature = EVP_VerifyFinal(&evp_md_ctx, signiture,
            SIGLEN, pub_key);

    fclose(fp);
    return is_valid_signature;

}


int rsa_encrypt(unsigned char* source,int inputsize, unsigned char* done,
 char* pempath){
    FILE* file;
    RSA* p_rsa;
    int encrypt_size;

    if((file=fopen(pempath,"r"))==NULL){
        printf("open key file error");
        return -1;    
    } 
    if((p_rsa = PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL)) == NULL){
        printf("RSA public key error\n");
        return -1;
    }

    if((encrypt_size = RSA_public_encrypt(inputsize,(unsigned char *)source,
        (unsigned char*)done,p_rsa,RSA_PKCS1_OAEP_PADDING)) < 0){
        printf("encrypt error\n");
        return -1;
    }
    RSA_free(p_rsa);
    fclose(file);
    return encrypt_size;
}


int rsa_decrypt(unsigned char* source,int outputsize,
                    unsigned char* done,
                char* pempath, char* passphrase){
    FILE* file;
    RSA *p_rsa;
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
    memcpy(done,buffer,sizeof(file_header));
    RSA_free(p_rsa);
    fclose(file);
    return 0;
}


int aes_encrypt(char *filepath, char *destination, unsigned char *key,
                unsigned int filesize, unsigned char* signiture){
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
    fseek(outfile,RSA_SIZE,SEEK_SET);
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
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
    memcpy(input+bytesRead, signiture, SIGLEN);

    for(i=0;i<9;++i){
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
                unsigned int filesize, unsigned char* signiture){
    unsigned char input[512];
    unsigned char buffer[512];
    unsigned char buffer2[512];
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];       // init vector
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

    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }
    int block = ceil(1.0 * filesize / AES_BLOCK_SIZE);
    for(i=0;i<block-1;++i){
        fread(input, 1, AES_BLOCK_SIZE, infile);
        AES_cbc_encrypt(input, buffer, AES_BLOCK_SIZE, &aes, iv, AES_DECRYPT);
        fwrite(buffer,1,AES_BLOCK_SIZE,outfile);
    }
    fread(input, 1, AES_BLOCK_SIZE * 9, infile);
    for(i=0;i<9;++i){
        AES_cbc_encrypt(input+i*AES_BLOCK_SIZE, buffer2+i * AES_BLOCK_SIZE, AES_BLOCK_SIZE, &aes, iv, AES_DECRYPT);
    }
    fwrite(buffer2,1,(filesize-1)%AES_BLOCK_SIZE+1, outfile);
    memcpy(signiture,buffer2+(filesize-1)%AES_BLOCK_SIZE + 1,SIGLEN);

    //decrypt signiture
    // fseek(infile,-8 * AES_BLOCK_SIZE, SEEK_END);
    // for(i=0;i<8;++i){
    //     fread(input,1,AES_BLOCK_SIZE,infile);
    //     AES_cbc_encrypt(input, signiture+i*AES_BLOCK_SIZE, AES_BLOCK_SIZE, 
    //         &aes, iv, AES_DECRYPT);
    // }

    fflush(outfile);
    fclose(infile);
    fclose(outfile);
    return 0;
}



int encrypt_file(char* filepath, char* lpri, char* spub, char* passphrase){
    struct file_header fh;
    // unsigned char buffer[BUFFER_SIZE];
    unsigned char* buffer;
    buffer = (unsigned char*)calloc(1,BUFFER_SIZE);


    char outpath[1024];
    sprintf(outpath, "%s.enc", filepath);
    FILE *outfile = fopen(outpath, "wb");
    if(!outfile){
        printf("Out File open error\n");
        return(NULL);
    }

    //Get file header K and filesize
    fh.filesize = getfilesize(filepath);
    sha256_file(filepath, fh.k);

    //Encrypt file header
    rsa_encrypt((unsigned char*)&fh,sizeof(fh), buffer, spub);
    //write encrypted file header to file

    if(fwrite(buffer, RSA_SIZE, 1, outfile) == 0){
        printf("file write errror\n");
        fclose(outfile);
        return(NULL);
    }
    fflush(outfile);
    fclose(outfile);

    //calculate signiture
    unsigned char signiture[SIGLEN];

    certfile(filepath, lpri, signiture, passphrase);

    aes_encrypt(filepath, outpath, fh.k, fh.filesize, signiture);

    free(buffer);
    return 0;
}

int decrypt_file(char* filepath, char* cert, char* spri, char* passphrase){
    FILE* file;
    // unsigned char buffer[BUFFER_SIZE];
    unsigned char signiture[SIGLEN];

    unsigned char* buffer;
    buffer = (unsigned char*)calloc(1,BUFFER_SIZE);

    file_header fh;
    char destination[512];
    sprintf(destination,"%s.txt",filepath);
    if((file = fopen( filepath, "r")) == NULL){
        printf("encrypted file open error");
        return NULL;
    }
    fread(buffer, RSA_SIZE, 1, file);
    fclose(file);
    rsa_decrypt(buffer, sizeof(file_header), (unsigned char*)&fh, spri,
        passphrase);
    printf("filesize:%d\n", fh.filesize);

    aes_decrypt(filepath, destination, fh.k, fh.filesize,signiture);

    free(buffer);

    if(cert_verify(signiture, destination, cert ,fh.filesize) == 1){
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
                //printf("decrypt mode\n");
                if(mode != 0){
                    fprintf(stderr, "set mode error\n");
                    exit(-1);
                }
                mode = 1;
                break;
                
            case 'f':
                //printf("filepath:%s\n", optarg);
                strcpy(filepath, optarg);
                break;
                
            case '1':
                //printf("cert:%s\n", optarg);
                strcpy(cert, optarg);
                break;
                
            case '2':
                //printf("lpri:%s\n", optarg);
                strcpy(lpri, optarg);
                break;

            case '3':
                //printf("spub:%s\n", optarg);
                strcpy(spub, optarg);
                break;

            case '4':
                //printf("spri:%s\n", optarg);
                strcpy(spri, optarg);
                break;

            case '5':
                //printf("lp:%s\n", optarg);
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
