/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/hmac.h>
#include <string.h>  /* memcpy */
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "ske.h"
#include "rsa.h"
#include "prf.h"
#define HM_LEN 32


//victor why
static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
#define HASHLEN 32 /* for sha256 */
size_t lenofRSA;

int kem_encrypt(const char* outputFileName, const char* inputFileName, RSA_KEY* rsaKey) {
    // Generate a random symmetric key using SKE
    size_t rsaKeySizeBytes = rsa_numBytesN(rsaKey);
    unsigned char* entropy = malloc(rsaKeySizeBytes);
    SKE_KEY symmetricKey;
    ske_keyGen(&symmetricKey, entropy, rsaKeySizeBytes);

    // Encapsulate entropy using RSA and SHA256
    unsigned char* rsaEncryptedEntropyWithHash = malloc(rsaKeySizeBytes + HASHLEN);
    unsigned char* hash = malloc(HASHLEN);
    SHA256(entropy, rsaKeySizeBytes, hash);
    rsa_encrypt(rsaEncryptedEntropyWithHash, entropy, rsaKeySizeBytes, rsaKey);
    memcpy(rsaEncryptedEntropyWithHash + rsaKeySizeBytes, hash, HASHLEN);

    // Write encapsulated entropy to the output file
    int outputFileDescriptor = open(outputFileName, O_RDWR | O_CREAT, S_IRWXU);

    int bytesWritten = write(outputFileDescriptor, rsaEncryptedEntropyWithHash, rsaKeySizeBytes + HASHLEN);

    close(outputFileDescriptor);

    // Encrypt the input file using the symmetric key
    unsigned char* initializationVector = malloc(16);
    randBytes(initializationVector, 16);
    ske_encrypt_file(outputFileName, inputFileName, &symmetricKey, initializationVector, rsaKeySizeBytes + HASHLEN);

    // Cleanup
    free(entropy);
    free(rsaEncryptedEntropyWithHash);
    free(hash);
    free(initializationVector);

    return 0;
}


/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* outputFileName, const char* inputFileName, RSA_KEY* rsaKey) {
    // Open the encrypted file and get its size
    int inputFileDescriptor;
    unsigned char* mappedFile;
    size_t fileSize;
    struct stat st;
    
    inputFileDescriptor = open(inputFileName, O_RDONLY);
    stat(inputFileName, &st);
    fileSize = st.st_size;

    // Map the encrypted file into memory
    mappedFile = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, inputFileDescriptor, 0);
    close(inputFileDescriptor);

    // Extract the RSA-encrypted entropy
    size_t rsaKeySizeBytes = rsa_numBytesN(rsaKey);
    unsigned char* encryptedEntropy = malloc(rsaKeySizeBytes);
    memcpy(encryptedEntropy, mappedFile, rsaKeySizeBytes);

    // Decrypt the RSA-encrypted entropy to retrieve the original entropy
    unsigned char* decryptedEntropy = malloc(rsaKeySizeBytes);
    rsa_decrypt(decryptedEntropy, encryptedEntropy, rsaKeySizeBytes, rsaKey);

    // Compute the hash of the decrypted entropy
    unsigned char* computedHash = malloc(HASHLEN);
    SHA256(decryptedEntropy, rsaKeySizeBytes, computedHash);

    // Extract the hash from the file
    unsigned char* fileHash = malloc(HASHLEN);
    memcpy(fileHash, mappedFile + rsaKeySizeBytes, HASHLEN);


    // Generate symmetric key from decrypted entropy
    SKE_KEY symmetricKey;
    ske_keyGen(&symmetricKey, decryptedEntropy, rsaKeySizeBytes);

    // Decrypt the input file using the symmetric key
    ske_decrypt_file(outputFileName, inputFileName, &symmetricKey, rsaKeySizeBytes + HASHLEN);

    // Cleanup
    munmap(mappedFile, fileSize);
    free(encryptedEntropy);
    free(decryptedEntropy);
    free(computedHash);
    free(fileHash);

    return 0;
}


int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h': // help
				printf(usage,argv[0],nBits);
				return 0;
			case 'i': // argument to fnIn
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o': 
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN); 
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

	
	RSA_KEY K; 
	
	// Define Variables to prevent redefinition error
	FILE* rsa_publicKey;
	FILE* rsa_privateKey;

	switch (mode) {
		case ENC:
			rsa_publicKey = fopen(fnKey,"r");
			rsa_readPublic(rsa_publicKey, &K);
			kem_encrypt(fnOut,fnIn,&K);
			fclose(rsa_publicKey);
			rsa_shredKey(&K);

			break;
		case DEC:
			rsa_privateKey = fopen(fnKey,"r");
			rsa_readPrivate(rsa_privateKey, &K);
			kem_decrypt(fnOut,fnIn,&K);

			fclose(rsa_privateKey);
			
			rsa_shredKey(&K);

			break;
		case GEN:
			rsa_keyGen(nBits,&K);
			rsa_privateKey = fopen(fnOut,"w+");
			rsa_writePrivate(rsa_privateKey, &K);
			strcat(fnOut,".pub");
			rsa_publicKey = fopen(fnOut,"w+");
			rsa_writePublic(rsa_publicKey, &K);

			fclose(rsa_privateKey);
			fclose(rsa_publicKey);

			rsa_shredKey(&K);
			break;
		default:
			return 1;
	}

	return 0;
}
