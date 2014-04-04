/*++
 Sha1.c

 Description : NIST Secure Hash Algorithm 
               heavily modified by Uwe Hollerbach uh@alumni.caltech edu 
               from Peter C. Gutmann's implementation as found in 
               Applied Cryptography by Bruce Schneier 

               NIST's proposed modification to SHA of 7/11/94 must be 
               activated by defining USE_MODIFIED_SHA 

--*/
#include "Sha1.h"
#include <memory.h>

#if defined(_MSC_VER)   // Microsoft C/C++
#if defined(_M_IX86)    // x86 platform
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN       1
#endif
#endif
#endif

#define USE_MODIFIED_SHA    1

/* SHA f()-functions */

/* SHA constants */

#define CONST1     0x5a827999L
#define CONST2     0x6ed9eba1L
#define CONST3     0x8f1bbcdcL
#define CONST4     0xca62c1d6L

#define f1(x,y,z)  (((x & y) | (~x & z)) + CONST1)
#define f2(x,y,z)  ((x ^ y ^ z) + CONST2)
#define f3(x,y,z)  (((x & y) | (x & z) | (y & z)) + CONST3)
#define f4(x,y,z)  ((x ^ y ^ z) + CONST4)

/* 32-bit rotate */

#define ROT32(x,n) ((x << n) | (x >> (32 - n)))

#define FUNC(n,i)                 \
    temp = ROT32(A,5) + f##n(B,C,D) + E + W[i];   \
    E = D; D = C; C = ROT32(B,30); B = A; A = temp

#ifdef LITTLE_ENDIAN

/* change endianness of data */
static 
void reverse_copy( 
unsigned long *out, 
unsigned long *in, 
unsigned long  count
)
{
    while (count > 0)
    {
        ((unsigned char*)out)[0] = ((unsigned char*)in)[3];
        ((unsigned char*)out)[1] = ((unsigned char*)in)[2];
        ((unsigned char*)out)[2] = ((unsigned char*)in)[1];
        ((unsigned char*)out)[3] = ((unsigned char*)in)[0];
        in++;
        out++;
        count--;
    }
} // reverse_copy

#endif /* LITTLE_ENDIAN */

// do SHA transformation 
static 
void 
sha_transform(
PSHA_INFO sha_info  // [in][out]
)
{
    int i;
    unsigned long temp, A, B, C, D, E, W[80];

#ifdef LITTLE_ENDIAN
    reverse_copy(W, sha_info->buffer.l, 16);
#else /* LITTLE_ENDIAN */
    for (i = 0; i < 16; ++i) {
        W[i] = sha_info->buffer.l[i];
    }
#endif /* LITTLE_ENDIAN */
    for (i = 16; i < 80; ++i) {
        W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
#ifdef USE_MODIFIED_SHA
        W[i] = ROT32(W[i], 1);
#endif /* USE_MODIFIED_SHA */
    }

    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];

    FUNC(1, 0);  FUNC(1, 1);  FUNC(1, 2);  FUNC(1, 3);  FUNC(1, 4);
    FUNC(1, 5);  FUNC(1, 6);  FUNC(1, 7);  FUNC(1, 8);  FUNC(1, 9);
    FUNC(1,10);  FUNC(1,11);  FUNC(1,12);  FUNC(1,13);  FUNC(1,14);
    FUNC(1,15);  FUNC(1,16);  FUNC(1,17);  FUNC(1,18);  FUNC(1,19);

    FUNC(2,20);  FUNC(2,21);  FUNC(2,22);  FUNC(2,23);  FUNC(2,24);
    FUNC(2,25);  FUNC(2,26);  FUNC(2,27);  FUNC(2,28);  FUNC(2,29);
    FUNC(2,30);  FUNC(2,31);  FUNC(2,32);  FUNC(2,33);  FUNC(2,34);
    FUNC(2,35);  FUNC(2,36);  FUNC(2,37);  FUNC(2,38);  FUNC(2,39);

    FUNC(3,40);  FUNC(3,41);  FUNC(3,42);  FUNC(3,43);  FUNC(3,44);
    FUNC(3,45);  FUNC(3,46);  FUNC(3,47);  FUNC(3,48);  FUNC(3,49);
    FUNC(3,50);  FUNC(3,51);  FUNC(3,52);  FUNC(3,53);  FUNC(3,54);
    FUNC(3,55);  FUNC(3,56);  FUNC(3,57);  FUNC(3,58);  FUNC(3,59);

    FUNC(4,60);  FUNC(4,61);  FUNC(4,62);  FUNC(4,63);  FUNC(4,64);
    FUNC(4,65);  FUNC(4,66);  FUNC(4,67);  FUNC(4,68);  FUNC(4,69);
    FUNC(4,70);  FUNC(4,71);  FUNC(4,72);  FUNC(4,73);  FUNC(4,74);
    FUNC(4,75);  FUNC(4,76);  FUNC(4,77);  FUNC(4,78);  FUNC(4,79);

    sha_info->digest[0] += A;
    sha_info->digest[1] += B;
    sha_info->digest[2] += C;
    sha_info->digest[3] += D;
    sha_info->digest[4] += E;
//  printf("\n%08X %08X %08X %08X %08X", sha_info->digest[0], sha_info->digest[1],
//      sha_info->digest[2], sha_info->digest[3], sha_info->digest[4]);
}

void SHA1_API
SHA1Init(
PSHA_INFO sha_info      
)
{
    sha_info->digest[0] = 0x67452301L;
    sha_info->digest[1] = 0xefcdab89L;
    sha_info->digest[2] = 0x98badcfeL;
    sha_info->digest[3] = 0x10325476L;
    sha_info->digest[4] = 0xc3d2e1f0L;
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    /**
    *** added by vp.
    **/
    memset(sha_info->buffer.b, 0, sizeof(sha_info->buffer.b));
} // Sha1Init 

void SHA1_API
SHA1Update( 
PSHA_INFO     sha_info,     
unsigned char *buffer,      
unsigned long  count        
)
{
    unsigned long i, n;
    i = sha_info->count_lo & 0x3f;
    sha_info->count_lo += count;
    if (sha_info->count_lo < count) sha_info->count_hi++;

    for (n = i + count; n >= 64; i = 0)
    {
        memcpy(&sha_info->buffer.b[i], buffer, 64-i);
        sha_transform(sha_info);
        buffer += (64-i);
        n -= (64-i);
    }

    if (n > i)
        memcpy(&sha_info->buffer.b[i], buffer, n-i);
} 

void SHA1_API
SHA1Final( 
unsigned char *digest,
PSHA_INFO     sha_info      
)
{
    int i = (int) (sha_info->count_lo & 0x3f);
    sha_info->buffer.b[i++] = 0x80;
    if (i > 56) {
        memset(&sha_info->buffer.b[i], 0, 64 - i);
        sha_transform(sha_info);
        memset(sha_info->buffer.b, 0, 56);
    }
    else{
        memset((unsigned char *) &sha_info->buffer + i, 0, 56 - i);
    }

    sha_info->buffer.b[56] = (unsigned char)(sha_info->count_hi >> 21);
    sha_info->buffer.b[57] = (unsigned char)(sha_info->count_hi >> 13);
    sha_info->buffer.b[58] = (unsigned char)(sha_info->count_hi >>  5);
    sha_info->buffer.b[59] = (unsigned char)((unsigned char)(sha_info->count_hi <<  3)|
                                             (unsigned char)(sha_info->count_lo >> 29));
    sha_info->buffer.b[60] = (unsigned char)(sha_info->count_lo >> 21);
    sha_info->buffer.b[61] = (unsigned char)(sha_info->count_lo >> 13);
    sha_info->buffer.b[62] = (unsigned char)(sha_info->count_lo >> 5);
    sha_info->buffer.b[63] = (unsigned char)(sha_info->count_lo << 3);
    sha_transform(sha_info);

#ifdef LITTLE_ENDIAN
    reverse_copy((unsigned long*)digest, sha_info->digest, 20/4);
#else /* LITTLE_ENDIAN */
    memcpy( digest, sha_info->digest, 20 );
#endif /* LITTLE_ENDIAN */
} 

unsigned char * SHA1_API
SHA1_Hash(
unsigned char *Message, 
unsigned long  Length,  
unsigned char *Digest   
)
{
    SHA_INFO      shaInfo;

    SHA1Init( &shaInfo );
    SHA1Update( &shaInfo, Message, Length );
    SHA1Final( Digest, &shaInfo );
    /* clear sensitive data */
    memset( &shaInfo, 0, sizeof(shaInfo) );
    return( Digest );
} 

