
#include "Ocall_wrappers.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <string.h>

#define	INADDR_NONE		((unsigned long int) 0xffffffff)
#define ECSIGSIZE 72
#define RSASIGSIZE 256
#define BUFLEN 4200
#define READFILE_BUFLEN 4096
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#define O_RDONLY       0x0000  /* open for reading only */
#define O_WRONLY       0x0001  /* open for writing only */
#define O_RDWR         0x0002  /* open for reading and writing */
#define O_APPEND       0x0008  /* writes done at eof */

#define O_CREAT        0x0100  /* create and open file */
#define O_TRUNC        0x0200  /* open and truncate */
#define O_EXCL         0x0400  /* open only if file doesn't already exist */

#define O_TEXT         0x4000  /* file mode is text (translated) */
#define O_BINARY       0x8000  /* file mode is binary (untranslated) */
#define O_WTEXT        0x10000 /* file mode is UTF16 (translated) */
#define O_U16TEXT      0x20000 /* file mode is UTF16 no BOM (translated) */
#define O_U8TEXT       0x40000 /* file mode is UTF8  no BOM (translated) */

static sgx_aes_gcm_128bit_key_t aes_key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
static EVP_MD_CTX *global_mdctx = NULL;
static char hmac_key[] = "hmac_test_key";
static unsigned int hmac_len = 32;
static unsigned char aes_key_256[] = "aes256gcmtestkey";
static unsigned char aes_iv[] = "aes256gcmtestiv";

int bsd_rand();     
int rseed = 0;      
char gv_flph[80];   // file we are going to check.
int debug = 0;      // debug level. 

static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static int
isascii(int c)
{
	return((c & ~0x7F) == 0);
}

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) + 
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
		printe("socket");
		exit(EXIT_FAILURE);
    }

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	printl("Connecting...");
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
        exit(EXIT_FAILURE);
	}

	return sockfd;
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// --------------------- 
// Function for signing the digest using hmac
// 作者：yasi_xi 
// 来源：CSDN 
// 原文：https://blog.csdn.net/yasi_xi/article/details/9066003 
int HmacEncode(const char * key, unsigned int key_length,
                const char * input, unsigned int input_length,
                unsigned char * &output, unsigned int &output_length) {
        const EVP_MD * engine = NULL;
        engine = EVP_sha256();
 
        output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
 
        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, key, key_length, engine, NULL);
        HMAC_Update(&ctx, (unsigned char*)input, strlen(input));   
 
        HMAC_Final(&ctx, output, &output_length);
        HMAC_CTX_cleanup(&ctx);
 
        return 0;
}

static char *binToHex(const unsigned char *bin, size_t len)
{
	char   *out;
	size_t  i;

	if (bin == NULL || len == 0)
		return NULL;

	out = (char*)malloc(len*2+1);
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
		out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';

	return out;
}

static void print_byte_in_hex(unsigned char *bytes, size_t len) {
	char* outputBuffer;
	outputBuffer = binToHex(bytes, len);
	printf("Bytes printed in hex: %s\n", outputBuffer);
}


static X509 *generateCertificate(const char *certStr)
{
    BIO *bio;
    X509 *cert;
    bio=BIO_new(BIO_s_mem());
    if(BIO_puts(bio,certStr) <= 0){
        printf("puts not succ\n");
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(cert == NULL){
        printf("no cert\n");
    }
    BIO_free(bio);
    return(cert);
}

static EVP_PKEY *generateKey(const char *keyStr)
{
    BIO *bio;
    EVP_PKEY *key;
    bio=BIO_new(BIO_s_mem());
    BIO_puts(bio,keyStr);
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if(key == NULL){
        printf("no key\n");
    }
    BIO_free(bio);
    return(key);
}


static EVP_PKEY *generatePubKey(const char *keyStr)
{
    BIO *bio;
    EVP_PKEY *key;
    bio=BIO_new(BIO_s_mem());
    BIO_puts(bio,keyStr);
    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(key == NULL){
        printf("no key\n");
    }
    BIO_free(bio);
    return(key);
}


static EC_KEY *generateECDSAKey(const char *keyStr)
{
    BIO *bio;
    EC_KEY *key;
    bio=BIO_new(BIO_s_mem());
    BIO_puts(bio,keyStr);
    key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    if(key == NULL){
        printf("no key\n");
    }
    BIO_free(bio);
    return(key);
}

static EC_KEY *generateECDSAPubKey(const char *keyStr)
{
    BIO *bio;
    EC_KEY *key;
    bio=BIO_new(BIO_s_mem());
    BIO_puts(bio,keyStr);
    key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    if(key == NULL){
        printf("no key\n");
    }
    BIO_free(bio);
    return(key);
}


RSA * createRSA(char * key,int isPublic)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create BIO of key");
        return 0;
    }
    if(isPublic)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA structure info");
    }
 
    return rsa;
}


//-------------------------------------------------------------------------------
/* Use Linear congruential generator(BSD) as the random number calculation result 
  is different on different plantform or use differnt compiler.   
*/
void bsd_srand(int x)
{
	rseed = x;
}

#define BSD_RAND_MAX ((1U << 31) - 1)
 
int bsd_rand()
{
	return rseed = (rseed * 1103515245 + 12345) & BSD_RAND_MAX;
}


void enclave_sign(char *fileIn, size_t len, unsigned char *MessageOut, size_t lenOut) {
	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	size_t* slen = (size_t*)OPENSSL_malloc(sizeof(size_t));
	int sizeread, fd;
	char buffer[READFILE_BUFLEN];

	unsigned char *sig = NULL;

	char *keyStr;
	ocall_readCKfile(&keyStr,"../LibAtt/certs/client.pkey");
	EVP_PKEY *pkey = generateKey(keyStr);

	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())) goto err;
	 
	// Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) goto err;
	 
	//  /* Call update with the message */
	fd = sgx_open(fileIn, O_RDONLY);
	if (fd < 0) {
		printf("cannot open read file\n");
		goto err;
	}
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	// printf("sizeread: %d\n", sizeread);
	while (sizeread > 0) {
		// printf("sizeread: %d\n", sizeread);
		if(1 != EVP_DigestSignUpdate(mdctx, (void*)buffer, sizeread)) goto err;
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	}

	sgx_close(fd);
	 
	//  Finalise the DigestSign operation 
	//  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	//   * signature. Length is returned in slen */
	if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
	//  /* Allocate memory for the signature based on size in slen */
	if(!(sig = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) goto err;

	//  /* Obtain the signature */
	if(1 != EVP_DigestSignFinal(mdctx, sig, slen)) goto err;

	memcpy(MessageOut,sig, *slen);

	ret = 1; 
	if (ret != 1) {
		err:
		    printf("unknown error\n");
	}
	 
	 /* Clean up */
	 if(*sig && !ret) OPENSSL_free((void*)sig);

	 if(mdctx) EVP_MD_CTX_destroy(mdctx);
}

int enclave_verify(char *fileIn, size_t len, unsigned char *sig, size_t siglen) {
	char *keyStr;
	ocall_readCKfile(&keyStr,"../LibAtt/certs/client.pub");
    EVP_PKEY *pubKey = generatePubKey(keyStr);

    EVP_MD_CTX *mdctx = NULL;
    if(!(mdctx = EVP_MD_CTX_create())) goto err;
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubKey)) goto err;

    int fd, sizeread;
    char buffer[READFILE_BUFLEN];
    fd = sgx_open(fileIn, O_RDONLY);
    sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
    while(sizeread > 0) {
    	if(1 != EVP_DigestVerifyUpdate(mdctx, buffer, sizeread)) goto err;
    	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
    }
    if(1 == EVP_DigestVerifyFinal(mdctx, sig, siglen)) {
    /* Success */
        printf("Enclave: verify success\n");
        return 1;
    } else {
    /* Failure */
        printf("Enclave: verify failure\n");
        return 0;
    }
    err:
        printf("Unknown error\n");
        return 0;
}


size_t enclave_sign_ecdsa(char *fileIn, size_t len, unsigned char *MessageOut, size_t lenOut) {
	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	size_t slen;
	int sizeread, fd;
	char buffer[READFILE_BUFLEN];

	unsigned char *sig = NULL;

	char *keyStr;
	ocall_readCKfile(&keyStr,"../LibAtt/certs/ecdsa.pkey");

	EVP_PKEY *pkey;
	EC_KEY *eckey = generateECDSAKey(keyStr);
	pkey = (EVP_PKEY*)OPENSSL_malloc(sizeof(EVP_PKEY));
	if(!(EVP_PKEY_assign_EC_KEY(pkey, eckey))) goto err;

	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())) goto err;
	 
	// Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey)) goto err;
	 
	//  /* Call update with the message */
	fd = sgx_open(fileIn, O_RDONLY);
	if (fd < 0) {
		printf("cannot open read file\n");
		goto err;
	}
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	// printf("sizeread: %d\n", sizeread);
	while (sizeread > 0) {
		// printf("sizeread: %d\n", sizeread);
		if(1 != EVP_DigestSignUpdate(mdctx, (void*)buffer, sizeread)) goto err;
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	}

	sgx_close(fd);
	 
	//  Finalise the DigestSign operation 
	//  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	//   * signature. Length is returned in slen */
	if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) goto err;
	//  /* Allocate memory for the signature based on size in slen */
	if(!(sig = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * slen))) goto err;
	//  /* Obtain the signature */
	if(1 != EVP_DigestSignFinal(mdctx, sig, &slen)) goto err;
	// print_byte_in_hex(sig, slen);

	memcpy(MessageOut,sig, slen);

	ret = 1; 
	if (ret != 1) {
		err:
		    printf("unknown error\n");
	}
	 
	 /* Clean up */
	 if(*sig && !ret) OPENSSL_free((void*)sig);

	 // EVP_MD_CTX_destroy(mdctx);
	 return slen;
}


int enclave_verify_ecdsa(char *fileIn, size_t len, unsigned char *sig, size_t siglen) {
	EVP_MD_CTX *mdctx;
	char *keyStr;
	ocall_readCKfile(&keyStr,"../LibAtt/certs/ecdsa.pub");

	EVP_PKEY *pKey;
	EC_KEY *eckey = generateECDSAPubKey(keyStr);

	// printf("key\n");

	pKey = (EVP_PKEY*)OPENSSL_malloc(sizeof(EVP_PKEY));
	if(!(EVP_PKEY_assign_EC_KEY(pKey, eckey))) goto err;

	// printf("assigned\n");

    if(!(mdctx = EVP_MD_CTX_create())) goto err;
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pKey)) goto err;

    int fd, sizeread;
    char buffer[READFILE_BUFLEN];
    fd = sgx_open(fileIn, O_RDONLY);
    sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
    while(sizeread > 0) {
    	if(1 != EVP_DigestVerifyUpdate(mdctx, buffer, sizeread)) goto err;
    	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
    }
    sgx_close(fd);

    print_byte_in_hex(sig, siglen);

    // printf("read\n");
    if(1 == EVP_DigestVerifyFinal(mdctx, sig, siglen)) {
    /* Success */
        printf("Enclave: verify success\n");
        return 1;
    } else {
    /* Failure */
        printf("Enclave: verify failure\n");
        return 0;
    }
    err:
        printf("Unknown error\n");
        return 0;
}

int enclave_sign_to_server(char* MessageIn, size_t len, int is_ecdsa) {
	// ============================
	// SIGNATURE
	// ============================
	int sigsize;
	if(is_ecdsa) {
		sigsize = ECSIGSIZE;
	} else {
		sigsize = RSASIGSIZE;
	}
	unsigned char* signature;
	size_t slen;
    signature = (unsigned char*)malloc(sigsize);
    if(is_ecdsa) {
    	slen = enclave_sign_ecdsa(MessageIn, len, signature, sigsize);
    } else {
    	enclave_sign(MessageIn, len, signature, sigsize);
    	slen = sigsize;
    }
    print_byte_in_hex(signature, slen);

	// ============================
	// HANDLE TLS CONNECTION
	// ============================
	SSL *ssl;
	int sock;
    SSL_CTX *ctx;
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    const char *serv_ip = "127.0.0.1";
    uint32_t serv_port = 5005;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    SSL_CTX_set_options(ctx, flags);

    // ============================
	// LOAD CERTS FROM FILE W OCALL
	// AND SET CERTS
	// ============================
    char *certStr,*keyStr, *caStr;
    ocall_readCKfile(&certStr,"../LibAtt/certs/client.cert");
    ocall_readCKfile(&keyStr,"../LibAtt/certs/client.pkey");
    ocall_readCKfile(&caStr, "../LibAtt/certs/CA.cert");

    if(SSL_CTX_use_certificate(ctx, generateCertificate(certStr)) <= 0){
        printf("no cert loaded into ctx\n");
    }

    if(SSL_CTX_use_PrivateKey(ctx, generateKey(keyStr)) <=0){
        printf("no private key loaded into ctx\n");
    }

    X509_STORE *ca_store = SSL_CTX_get_cert_store(ctx);
    if(X509_STORE_add_cert(ca_store, generateCertificate(certStr))<=0){
        printf("no CA cert loaded into ctx\n");
    }

    sock = create_socket_client(serv_ip, serv_port);
    printl("Connects to TLS server success");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    int ret = SSL_connect(ssl);
    printl("SSL_connect returned");

	if (ret <= 0) {
        printe("SSL_connect");
        int error = SSL_get_error(ssl, ret);
        exit(EXIT_FAILURE);
	}

	printl("ciphersuit: %s", SSL_get_current_cipher(ssl)->name);

	// ============================
	// SEND MESSAGE AND SIG TO SERVER
	// ============================
	

    SSL_write(ssl, signature, sigsize);
    if(is_ecdsa) {
    	SSL_write(ssl, &slen, sizeof(size_t));
    }

	int fd, sizeread;
	char buffer[READFILE_BUFLEN];
	fd = sgx_open(MessageIn, O_RDONLY);
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		SSL_write(ssl, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	} 

    printl("Starting to close SSL/TLS client");
    
    free(signature);
	SSL_free(ssl);
    SSL_CTX_free(ctx);
    sgx_close(sock);
    cleanup_openssl();

    return 1;
}

int enclave_verify_from_server(long int size, char* MessageIn, size_t len, int is_ecdsa) {
	// ============================
	// HANDLE TLS CONNECTION
	// ============================
	SSL *ssl;
	int sock;
    SSL_CTX *ctx;
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    const char *serv_ip = "127.0.0.1";
    uint32_t serv_port = 5005;
    size_t sigsize;
    size_t slen;
    if(is_ecdsa) {
    	sigsize = ECSIGSIZE;
    } else {
    	sigsize = RSASIGSIZE;
    }

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    SSL_CTX_set_options(ctx, flags);

    // ============================
	// LOAD CERTS FROM FILE W OCALL
	// AND SET CERTS
	// ============================
    char *certStr,*keyStr, *caStr;
    ocall_readCKfile(&certStr,"../LibAtt/certs/client.cert");
    ocall_readCKfile(&keyStr,"../LibAtt/certs/client.pkey");
    ocall_readCKfile(&caStr, "../LibAtt/certs/CA.cert");

    if(SSL_CTX_use_certificate(ctx, generateCertificate(certStr)) <= 0){
        printf("no cert loaded into ctx\n");
    }

    if(SSL_CTX_use_PrivateKey(ctx, generateKey(keyStr)) <=0){
        printf("no private key loaded into ctx\n");
    }

    X509_STORE *ca_store = SSL_CTX_get_cert_store(ctx);
    if(X509_STORE_add_cert(ca_store, generateCertificate(certStr))<=0){
        printf("no CA cert loaded into ctx\n");
    }

    sock = create_socket_client(serv_ip, serv_port);
    printl("Connects to TLS server success");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    int ret = SSL_connect(ssl);
    printl("SSL_connect returned");

	if (ret <= 0) {
        printe("SSL_connect");
        int error = SSL_get_error(ssl, ret);
        exit(EXIT_FAILURE);
	}

	printl("ciphersuit: %s", SSL_get_current_cipher(ssl)->name);

	// ============================
	// SEND MESSAGE TO SERVER
	// ============================
	// SSL_write(ssl, &len, sizeof(size_t));
	// printf("%s\n", Message);
	int fd, sizeread;
	char buffer[READFILE_BUFLEN];

	SSL_write(ssl, &size, sizeof(long int));

	fd = sgx_open(MessageIn, O_RDONLY);
	if (fd < 0) {
		printe("cannot open file");
		exit(1);
	}
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		SSL_write(ssl, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	}

	unsigned char* signature;
    signature = (unsigned char*)malloc(sigsize);
    SSL_read(ssl, signature, sigsize);
    if(is_ecdsa) {
    	SSL_read(ssl, &slen, sizeof(size_t));
    	sigsize = slen;
    }

    printl("Starting to close SSL/TLS client");
    
    sgx_close(sock);
	SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    
    print_byte_in_hex(signature, sigsize);
    printf("signature size: %lu\n", sigsize);

    int ret2;
    if (is_ecdsa) {
    	ret2 = enclave_verify_ecdsa(MessageIn, len, signature, sigsize);
    } else {
    	ret2 = enclave_verify(MessageIn, len, signature, RSASIGSIZE);
    }
    if(ret2 == 1) {
    	printl("verify success");
    } else {
    	printl("verify failure");
    }

 //    printl("Starting to close SSL/TLS client");
    
 //    SSL_free(ssl);
 //    SSL_CTX_free(ctx);
 //    sgx_close(sock);
 //    cleanup_openssl();

    return 1;
}


void enclave_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		&aes_key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}

void enclave_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_rijndael128GCM_decrypt(
		&aes_key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
        //emit_debug((char *) p_dst);
		
	
}

void enclave_encrypt_aes_256gcm(char *from, size_t fromlen, char *to, size_t tolen) {
	// set up key and init
	const EVP_CIPHER *cipher;
	cipher = EVP_aes_256_gcm();
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, cipher, aes_key_256, aes_iv);

	// read file and update
	int fdfrom, fdto, sizeread, sizetowrite, sizewritten;
    unsigned char rbuffer[READFILE_BUFLEN];
    unsigned char wbuffer[READFILE_BUFLEN + 256];

    fdfrom = sgx_open(from, O_RDONLY);
    fdto = sgx_open(to, O_WRONLY);

    sizeread = sgx_read(fdfrom, rbuffer, READFILE_BUFLEN);
    while(sizeread > 0) {
    	EVP_EncryptUpdate(ctx, wbuffer, &sizetowrite, rbuffer, sizeread);
    	sizewritten = sgx_write(fdto, wbuffer, sizetowrite);
    	if(sizewritten != sizetowrite) {
    		printf("Error in writing\n");
    	}
    	sizeread = sgx_read(fdfrom, rbuffer, READFILE_BUFLEN);
    }

    EVP_EncryptFinal(ctx, wbuffer, &sizetowrite);
    sizewritten = sgx_write(fdto, wbuffer, sizetowrite);
    if(sizewritten != sizetowrite) {
   		printf("Error in writing\n");
   	}

   	sgx_close(fdfrom);
   	sgx_close(fdto);
}

void enclave_decrypt_aes_256gcm(char *from, size_t fromlen, char *to, size_t tolen) {
	const EVP_CIPHER *cipher;
	cipher = EVP_aes_256_gcm();
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, cipher, aes_key_256, aes_iv);

	// read file and update
	int fdfrom, fdto, sizeread, sizetowrite, sizewritten;
    unsigned char rbuffer[READFILE_BUFLEN];
    unsigned char wbuffer[READFILE_BUFLEN + 256];

    fdfrom = sgx_open(from, O_RDONLY);
    fdto = sgx_open(to, O_WRONLY);

    sizeread = sgx_read(fdfrom, rbuffer, READFILE_BUFLEN);
    while(sizeread > 0) {
    	EVP_DecryptUpdate(ctx, wbuffer, &sizetowrite, rbuffer, sizeread);
    	sizewritten = sgx_write(fdto, wbuffer, sizetowrite);
    	if(sizewritten != sizetowrite) {
    		printf("Error in writing\n");
    	}
    	sizeread = sgx_read(fdfrom, rbuffer, READFILE_BUFLEN);
    }

    EVP_DecryptFinal(ctx, wbuffer, &sizetowrite);
    sizewritten = sgx_write(fdto, wbuffer, sizetowrite);
    if(sizewritten != sizetowrite) {
   		printf("Error in writing\n");
   	}

   	sgx_close(fdfrom);
   	sgx_close(fdto);
}

void enclave_digest(char *fileIn, size_t len, unsigned char *MessageOut, size_t lenOut) {
	unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    int fd, sizeread;
	char buffer[READFILE_BUFLEN];
	fd = sgx_open(fileIn, O_RDONLY);
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		SHA256_Update(&sha256, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	} 
    
    SHA256_Final(hash, &sha256);
	memcpy(MessageOut, hash, SHA256_DIGEST_LENGTH);
}

void enclave_hmac(char *fileIn, size_t len, unsigned char *MessageOut, size_t lenOut) {
	const EVP_MD *engine = EVP_sha256();
	unsigned int slen;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, hmac_key, strlen(hmac_key), engine, NULL);
	int fd, sizeread;
	unsigned char buffer[READFILE_BUFLEN];
	fd = sgx_open(fileIn, O_RDONLY);
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		HMAC_Update(&ctx, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	}
	HMAC_Final(&ctx, MessageOut, &slen);
	HMAC_CTX_cleanup(&ctx);
}

int enclave_verify_hmac(char *fileIn, size_t len, unsigned char *HmacIn, size_t lenIn) {
	int ret = -1;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	const EVP_MD *engine = EVP_sha256();
	unsigned int slen;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, hmac_key, strlen(hmac_key), engine, NULL);
	int fd, sizeread;
	unsigned char buffer[READFILE_BUFLEN];
	fd = sgx_open(fileIn, O_RDONLY);
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		HMAC_Update(&ctx, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	}
	HMAC_Final(&ctx, hash, &slen);
	HMAC_CTX_cleanup(&ctx);

	ret = 1;
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (HmacIn[i] != hash[i]) {
			ret = 0;
		}
	}

	if (ret = 1) {
		printf("Enclave: Verify Success\n");
	} else {
		printf("Enclave: Verify Failure\n");
	}

	return ret;
}

int enclave_verify_hmac_server(char* MessageIn, size_t len) {
	// ============================
	// HANDLE TLS CONNECTION
	// ============================
	SSL *ssl;
	int sock;
    SSL_CTX *ctx;
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    const char *serv_ip = "127.0.0.1";
    uint32_t serv_port = 5005;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    SSL_CTX_set_options(ctx, flags);

    // ============================
	// LOAD CERTS FROM FILE W OCALL
	// AND SET CERTS
	// ============================
    char *certStr,*keyStr, *caStr;
    ocall_readCKfile(&certStr,"../LibAtt/certs/client.cert");
    ocall_readCKfile(&keyStr,"../LibAtt/certs/client.pkey");
    ocall_readCKfile(&caStr, "../LibAtt/certs/CA.cert");

    if(SSL_CTX_use_certificate(ctx, generateCertificate(certStr)) <= 0){
        printf("no cert loaded into ctx\n");
    }

    if(SSL_CTX_use_PrivateKey(ctx, generateKey(keyStr)) <=0){
        printf("no private key loaded into ctx\n");
    }

    X509_STORE *ca_store = SSL_CTX_get_cert_store(ctx);
    if(X509_STORE_add_cert(ca_store, generateCertificate(certStr))<=0){
        printf("no CA cert loaded into ctx\n");
    }

    sock = create_socket_client(serv_ip, serv_port);
    printl("Connects to TLS server success");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    int ret = SSL_connect(ssl);
    printl("SSL_connect returned");

	if (ret <= 0) {
        printe("SSL_connect");
        int error = SSL_get_error(ssl, ret);
        exit(EXIT_FAILURE);
	}

	printl("ciphersuit: %s", SSL_get_current_cipher(ssl)->name);

	// ============================
	// SEND MESSAGE AND SIG TO SERVER
	// ============================
	unsigned char* signature;
    signature = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    enclave_hmac(MessageIn, len, signature, SHA256_DIGEST_LENGTH);
    print_byte_in_hex(signature, SHA256_DIGEST_LENGTH);

    SSL_write(ssl, signature, SHA256_DIGEST_LENGTH);

	int fd, sizeread;
	char buffer[READFILE_BUFLEN];
	fd = sgx_open(MessageIn, O_RDONLY);
	sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	while(sizeread > 0) {
		SSL_write(ssl, buffer, sizeread);
		sizeread = sgx_read(fd, buffer, READFILE_BUFLEN);
	} 

    printl("Starting to close SSL/TLS client");
    
	SSL_free(ssl);
    SSL_CTX_free(ctx);
    sgx_close(sock);
    cleanup_openssl();

    return 1;
}


//-------------------------------------------------------------------------------
int getSWATT(char challengeB[], int cSize, int m, int n, int puff)
{   
// challengeB[] : a random challenge string
//  cSize       : challenge string size
//  (m, n)      : m-swap list size(must >=260), n-sample times in one block.

    strncpy(gv_flph, "firmwareSample", 16); // ?
    char *ret;
    ocall_readFileBytes(&ret, gv_flph); // file array[128000] why is it hardcoded???
    char *challenge = challengeB;
    int keylen = cSize;

    // reference func: string_to_list <IOT_ATT.py>
    // convert string to integer array
    int challengeInt[keylen];
    for (int t = 0; t < keylen; t++)
    {
        challengeInt[t] = (int)challenge[t];
        if (debug == 1)
            printf(":<%d>\n", challengeInt[t]);
    }

    // reference func: setKey <IOT_ATT.py>
    // 反正就是set了一个key
    int state[m];
    for (int i = 0; i < m; i++)
    {
        state[i] = i;
    }
    int j = 0;
    for (int i = 0; i < m; i++)
    {
        j = (j + state[i] + challengeInt[i % keylen]) % m;
        int tmp = state[i];
        state[i] = state[j];
        state[j] = tmp;
    }
    
    // reference func: extract_CRpair <IOT_ATT.py>
    int s = 1;  
    int k = 16;
    int final = ((1 << k) - 1) & (puff >> (s - 1));
    if (debug == 1)
        printf("Extract bytes final:<%d>\n", final);
    int test[keylen];
    for (int t = 0; t < keylen; t++)
        test[t] = challengeInt[t] ^ final;
    for (int t = 0; t < keylen-1; t++)
        final += test[t] << 2;

    
    // main loop of the SWATT
    int cr_response = final;
    int pprev_cs = state[256];
    int prev_cs = state[257];
    int current_cs = state[258];
    int init_seed = m;
    int swatt_seed = 0; 
    for (int i = 0; i < n; i++)
    {
        swatt_seed = cr_response ^ init_seed;
        int Address = (state[i] << 8) + prev_cs;
        bsd_srand(Address);
        Address = bsd_rand() % 128000 + 1;
        char strTemp = ret[Address];
        if (debug == 1)
        {
            printf("R2:<%c>\n", strTemp);
            printf("R3:<%d>\n", current_cs);
            printf("R4:<%d>\n", pprev_cs);
        }
        int num = i - 1;
        if (num < 0)
            num = m - 1;
        current_cs = current_cs +((int)strTemp ^ pprev_cs + state[num]);
        init_seed = current_cs+swatt_seed;
        current_cs = current_cs >> 1; 
        pprev_cs = prev_cs;
        prev_cs = current_cs;
    }
    return current_cs;
}

int enclave_SWATT(unsigned char* in, int inlen) {
	int ret;
	int m = 300; 
    int n = 100;
    int puff = 1549465112;

    char *keyStr;
	RSA *rsa;
    ocall_readCKfile(&keyStr, "../LibAtt/certs/client.pkey");
    rsa = createRSA(keyStr, 0);

    int padding = RSA_PKCS1_PADDING;
    char out[4096];
    int outlen = RSA_private_decrypt(inlen, (const unsigned char*)in, (unsigned char*)out, rsa, padding);
    if(outlen == -1) {
    	printf("Encryption error\n");
    }

	ret = getSWATT(out, outlen, m, n, puff);
	printl("File swatt value :<%d>\n", ret);

	return ret;
}
