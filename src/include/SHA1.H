#ifndef _SHA1_HEADER_FILE
#define _SHA1_HEADER_FILE
#ifdef __cplusplus
extern "C" {
#endif

/*
 ***********************************************************************
 ** SHA-1 wrapper functions
 ***********************************************************************
 */

#ifdef _WIN32
#define SHA1_API _stdcall
#else
#define SHA1_API
#endif

/* SHA1 information record */
typedef struct _SHA_INFO {
    unsigned long digest[5];                /* message digest               */
    unsigned long count_lo;                 /* byte count-lo                */
    unsigned long count_hi;                 /* byte count-hi                */
    union
    {
        unsigned char b[64];
        unsigned long l[16];
    } buffer;                               /* SHA data buffer              */
} SHA_INFO, *PSHA_INFO;

#define SHA_BLOCKSIZE           64          /* block size for SHA           */
#define SHA_DIGESTSIZE          20          /* digest size for SHA          */

/* Initialize hash state */
void SHA1_API SHA1Init(
    PSHA_INFO sha_info);

/* Update hash state */
void SHA1_API SHA1Update( 
    PSHA_INFO     sha_info,     
    unsigned char *buffer,      
    unsigned long  count);

/* Finalize hash state */
void SHA1_API SHA1Final( 
    unsigned char *digest,
    PSHA_INFO      sha_info);

/* Perform a complete hash (init,update,final) */
unsigned char * SHA1_API SHA1_Hash( 
    unsigned char * Message,
    unsigned long   Length,
    unsigned char * Digest);

#ifdef __cplusplus
}
#endif

#endif
