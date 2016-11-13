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

int encRSA( char *filename, char *original, char *encrypted ) {
    FILE *f;
    RSA *rsa;
    int padding = RSA_PKCS1_OAEP_PADDING;
    int enclen, rsa_len;

    if( (f = fopen(filename, "r")) != NULL ) {
        rsa = PEM_read_RSA_PUBKEY(f,NULL,NULL,NULL);
        fclose(f);
    } else {
        perror("Open file error");
        return 1;
    }

    padding = RSA_PKCS1_OAEP_PADDING;
    rsa_len = RSA_size(rsa);

    memset( encrypted, 0, MAX_SIZE );
    if ( (enclen = RSA_public_encrypt( strlen(original), (unsigned char *)original, encrypted, rsa, padding )) < 0 ) {
        return 1;
    }
    RSA_free(rsa);

    return enclen;
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

    printf("Enc length : %d\n", strlen(encrypted));

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

    FILE *f;
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
    char *bob_pub = "bob.key";
    char *session, *iv;
    int sizebuf[1];
    char buffer[MAX_SIZE];
    char buffer2[MAX_SIZE];
    char backup[20];
    char *bob_public;
    char *req_msg1, *req_msg2;
    char *req_msg_attack = "{\"Remark\": \"If you have any question, please mail to any TA ASAP.\", \"Favorite_Snack\": \"PineApplePie\", \"Authentication_Code\": \"a40e00df6a6df9ab0fcb943611867dc76b96a0f72866c3a428be824a876d48c9\", \"Account_ID\": \"0556074\", \"Account_Money\": \"0\", \"Feedback\": \"How is the midterm exam? Good?\", \"Favorite_Fruit\": \"Apple\", \"Favorite_Song\": [\"P\", \"P\", \"A\", \"P\"]}";

    // Alice : 140.113.194.88 port 50000
    bzero( (char *)&destA, sizeof(destA) );
    destA.sin_family = AF_INET;
    destA.sin_addr.s_addr = inet_addr("140.113.194.88");
    destA.sin_port = htons(50000);

    // Bob   : 140.113.194.88 port 50005
    bzero( (char *)&destB, sizeof(destB) );
    destB.sin_family = AF_INET;
    destB.sin_addr.s_addr = inet_addr("140.113.194.88");
    destB.sin_port = htons(50500);

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
    printf( "<----- Alice -----> \n" );
    printf( "Send : %s\n", studentId );
    sender( sock_a, studentId, strlen(studentId) );
    receiver( sock_a, sizebuf, buffer );
    printf( "Receive : %s\n", buffer );

    // Receive bob's public key
    printf( "<------ Bob ------> \n" );
    printf( "Send : hello\n" );
    sender( sock_b, hello, 5 );
    receiver( sock_b, sizebuf, buffer2 );
    //bob_public = calloc( sizeof(char) , sizebuf[0]+1 );
    //memcpy( bob_public, buffer2, sizebuf[0]+1 );
    //bob_public = strdup( buffer2 );
    //printf( "Bob's public : \n%s\n", bob_public );

    // Store Bob's public key
    f = fopen(bob_pub,"w");
    fprintf(f, "%s", buffer2 );
    fclose(f);

    cleanbuf( sizebuf, buffer, buffer2 );

    // Read my public key
    if( (fd = open( "./mykey/public.key", O_RDONLY )) == -1 ) {
        perror("Cannot open public key. ");
        return 1;
    }

    fstat( fd, &sb );
    start = mmap( NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0 );
    if ( start == MAP_FAILED ){
        perror("Map failed.");
        return 1;
    }

    printf( "<----- Alice -----> \n" );

    // Send my public key to alice
    sender( sock_a, start, sb.st_size );
    close( fd );

    // Receive RSA(aes session key , initial vec) from alice
    receiver( sock_a, sizebuf, buffer );
    len = decRSA( sizebuf[0], buffer, buffer2 );
    session = strdup( buffer2 );
    cleanbuf( sizebuf, buffer, buffer2 );
    printf("Session length : %d\n", len);
    printf("Session key    : \n%s\n", session);

    receiver( sock_a, sizebuf, buffer );
    len = decRSA( sizebuf[0], buffer, buffer2 );
    iv = strdup( buffer2 );
    cleanbuf( sizebuf, buffer, buffer2 );
    printf("IV length : %d\n", len);
    printf("Initial Vector : \n%s\n", iv);

    // Receive AES(request msg1) from alice
    receiver( sock_a, sizebuf, buffer );
    decAES( session, iv, sizebuf[0], buffer, buffer2 );
    req_msg1 = strdup( buffer2 );
    cleanbuf( sizebuf, buffer, buffer2 );
    printf("Request MSG1 : \n%s\n", req_msg1);

    printf( "<------ Bob ------> \n" );

    // Send RSA(session, iv) to Bob
    len = encRSA( bob_pub, session, buffer );
    printf("Encrypted session key length : %d\n", len);
    sender( sock_b, buffer, len);

    len = encRSA( bob_pub, iv, buffer2 );
    printf("Encrypted iv key length : %d\n", len);
    sender( sock_b, buffer2, len);

    cleanbuf( sizebuf, buffer, buffer2 );

    // Send AES(req_msg_attack) to Bob
    //encAES( session, iv, strlen(req_msg_attack), req_msg_attack, buffer  );
    //sender( sock_b, buffer, strlen(req_msg_attack)+1 );     //weird
    encAES( session, iv, strlen(req_msg1), req_msg1, buffer  );
    sender( sock_b, buffer, strlen(req_msg1)+1 );     //weird

    cleanbuf( sizebuf, buffer, NULL );

    // Receive Response msg1
    receiver( sock_b, sizebuf, buffer );
    decAES( session, iv, sizebuf[0], buffer, buffer2 );
    printf("Response MSG1 : \n%s\n", buffer2);

    cleanbuf( sizebuf, buffer, buffer2 );

    // Receive "bye"
    receiver( sock_b, sizebuf, buffer );
    printf("Receive : %s\n", buffer );

    printf( "<----- Alice -----> \n" );

    // Send the msg to alice
    encAES( session, iv, strlen(buffer), buffer, buffer2 );
    sender( sock_a, buffer2, strlen(buffer2) );

    cleanbuf( sizebuf, NULL , buffer2 );

    receiver( sock_a, sizebuf, buffer );
    printf("Receive : %s\n", buffer );

    return 0;

}
