#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#define MAX_SIZE 4096

uint32_t numTransferEndian(uint32_t input){
    uint32_t swapped;
    swapped = ((input>>24)&0xff)    | // move byte 3 to byte 0
              ((input<<8)&0xff0000) | // move byte 1 to byte 2
              ((input>>8)&0xff00)   | // move byte 2 to byte 1
              ((input<<24)&0xff000000); // byte 0 to byte 3
    return swapped;
}

int sender( int sockfd, char *str, int length ) {
    int len;
    // send the length of string
    len = numTransferEndian(htonl(length));
    if ( send( sockfd, &len, sizeof(uint32_t), 0 ) == -1 ) {
        perror("Send failed.");
        return 1;
    }

    // send the original data
    if ( send( sockfd, str, length, 0 ) == -1 ) {
        perror("Send failed.");
        return 1;
    }

    return 0;

}

int receiver( int sockfd, int *sizebuf, char *buf ) {

    // Receive Length
    if ( recv( sockfd, sizebuf, sizeof(int), 0 ) == -1 ) {
        perror("Receive failed.");
        return 1;
    }

    // Receive data
    if (  recv( sockfd, buf, sizebuf[0], 0 ) == -1 ) {
        perror("Receive failed.");
        return 1;
    }

    return 0;

}

void cleanbuf ( int *sizebuf, char *buf, char *buf2 ) {

    if ( sizebuf != NULL )
        memset( sizebuf, 0, 1 );
    if ( buf != NULL )
        memset( buf, 0, MAX_SIZE );
    if ( buf2 != NULL )
        memset( buf2, 0, MAX_SIZE );

}

int decRSA( int len, char *src, char *dst ) {

    FILE *f;
    RSA *rsa;
    int padding = RSA_PKCS1_OAEP_PADDING;
    int plainlen;

    if( ( f = fopen("./mykey/private.key","r") ) == NULL ) {
        perror("Cannot open private key");
        return -1;
    }

    rsa = PEM_read_RSAPrivateKey(f,NULL,NULL,NULL);
    plainlen = RSA_private_decrypt( len, src, dst, rsa, padding );

    RSA_free(rsa);

    return plainlen;

}

int encAES( char *key, char *iv, int len, char *msg, char *encrypted ) {

    AES_KEY aes;
    char *backup_iv;

    // Backup the iv value
    backup_iv = malloc( sizeof(char) * strlen(iv) + 1 );
    strncpy( backup_iv, iv, strlen(iv)+1 );

    // Set AES encrypt key
    if( AES_set_encrypt_key(key, 256, &aes) < 0 ) {
        perror("AES set encrypt key failed");
        return 1;
    }

    printf("Origin Msg : %s\n", msg);
    printf("Msg length : %d\n", len);

    // Encrypt Message
    AES_cbc_encrypt( msg, encrypted, len, &aes, backup_iv, AES_ENCRYPT );
    free(backup_iv);

}

int decAES( char *key, char *iv, int len, char *msg, char *decrypted ) {

    AES_KEY aes;
    char *backup_iv;

    // Backup the iv value
    backup_iv = malloc( sizeof(char) * strlen(iv) + 1 );
    strncpy( backup_iv, iv, strlen(iv)+1 );

    // Set AES decrypt key
    if( AES_set_decrypt_key(key, 256, &aes) < 0 ) {
        perror("AES set decrypt key failed");
        return 1;
    }

    // Decrypt message
    AES_cbc_encrypt( msg, decrypted, len, &aes, backup_iv, AES_DECRYPT);
    free(backup_iv);

    return 0;

}

int main(){

    int sock_a, sock_b, fd;
    int sock_getlen, i;
    struct sockaddr_in destA, destB;
    struct stat sb;             // file info.
    uint32_t len;               // send to socket
    ssize_t numbytes;           // read return value
    void *start;
    char *bufptr;
    char *hello = "hello";
    char *studentId = "0556074";
    char *session, *iv;
    int sizebuf[1];
    char buffer[MAX_SIZE];
    char buffer2[MAX_SIZE];
    char backup[20];

    // Alice : 140.113.194.88 port 50000
    bzero( (char *)&destA, sizeof(destA) );
    destA.sin_family = AF_INET;
    destA.sin_addr.s_addr = inet_addr("140.113.194.88");
    destA.sin_port = htons(50000);

    // Bob   : 140.113.194.88 port 50005
    bzero( (char *)&destB, sizeof(destB) );
    destB.sin_family = AF_INET;
    destB.sin_addr.s_addr = inet_addr("140.113.194.88");
    destB.sin_port = htons(50005);

    // Create socket to alice & bob
    if ( (sock_a = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        perror("Cannot open socket.");
    if ( (sock_b = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        perror("Cannot open socket.");

    // Connect to alice & bob
    if ( connect( sock_a, (struct sockaddr *)&destA, sizeof(destA) ) < 0 )
        perror("Cannot connect to server");
    if ( connect( sock_b, (struct sockaddr *)&destB, sizeof(destB) ) < 0 )
        perror("Cannot connect to server");

    // Send Student ID to Alice
    sender( sock_a, studentId, strlen(studentId)+1 );
    receiver( sock_a, sizebuf, buffer );
    printf( "Receive : %s\n", buffer );

    return 0;

}
