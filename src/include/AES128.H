#ifndef _AES128_H_
#define _AES128_H_

typedef struct
{
    unsigned char round_key[16*11];
} AES128_CONTEXT, *PAES128_CONTEXT;

extern void AES128_LoadKey(
    PAES128_CONTEXT ac,
    unsigned char * key );

extern void AES128_Encrypt(
    PAES128_CONTEXT ac,
    unsigned char * data );

extern void AES128_Decrypt(
    PAES128_CONTEXT ac,
    unsigned char * data );

extern void AES128_EncryptXor(
    PAES128_CONTEXT ac,
    unsigned char * data,
    unsigned char * feedback );

extern void AES128_EncryptBlock(
    PAES128_CONTEXT ac,
    unsigned char * pData,
    unsigned long   Size );

extern void AES128_DecryptBlock(
    PAES128_CONTEXT ac,
    unsigned char * pData,
    unsigned long   Size );

extern int AES128_KAT( void );

#endif
