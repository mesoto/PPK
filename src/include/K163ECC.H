// Software only ECC support for K163

// Curve:   y^2 + xy = x^3 + x^2 + 1

// --------------------------------------------------------------------------
//
// --------------------------------------------------------------------------
#define K163_FIELD_BITS         163
#define K163_FIELD_BYTES        ((K163_FIELD_BITS+7)/8)

typedef struct 
{
    unsigned char X[K163_FIELD_BYTES];
    unsigned char Y[K163_FIELD_BYTES];
} K163_POINT, * PK163_POINT;

typedef struct 
{
    unsigned char X[K163_FIELD_BYTES];
    unsigned char Y[K163_FIELD_BYTES];
    unsigned char Order[K163_FIELD_BYTES];
} K163_BASE, * PK163_BASE;

typedef struct 
{
    unsigned char R[K163_FIELD_BYTES];
    unsigned char S[K163_FIELD_BYTES];
} K163_SIGNATURE, * PK163_SIGNATURE;

extern K163_POINT K163_BasePoint;
extern unsigned char K163_BasePointOrder[K163_FIELD_BYTES];

void K163_CreateSharedKey(
    PK163_POINT     PublicKey,              // [in]
    unsigned long   Flags,                  // [in]
    unsigned char * Multiplier,             // [in]
    unsigned long   MultiplierSize,         // [in]
    unsigned char * SessionInfo,            // [out][21 bytes]
    unsigned char * SharedKey );            // [out][16 bytes]

// Flags used by K163_CreateSharedKey is same the ones used by GNS_KeyExchange

int K163_ECDSAVerify(
    unsigned char    * MsgDigest,           // [in] 20 bytes
    PK163_POINT        PubKey,              // [in]
    PK163_SIGNATURE    Sig );               // [in]

int K163_ECSSHVerify(
    unsigned char    * MsgDigest,           // [in] 20 bytes
    PK163_POINT        PubKey,              // [in]
    PK163_SIGNATURE    Sig );               // [in]

void K163_CalculatePublicKey(
    unsigned char * PrivateKey,             // [in]
    unsigned long   Size,                   // [in]
    PK163_POINT     PublicKey );            // [out]

void K163_XOnlyMultiply( 
    unsigned char * x,                      // [in]
    unsigned char * multiplier,             // [in]
    int size,                               // [in]
    unsigned char * w );                    // [out]

void K163_SSHSignature( 
    unsigned char  * d,         // [in] Private key, 21 bytes
    unsigned char  * m,         // [in] h(m), 20 bytes
    K163_SIGNATURE * Sig );     // [out] sig

void K163_DSASignature( 
    unsigned char  * d,         // [in] Private key, 21 bytes
    unsigned char  * m,         // [in] h(m), 20 bytes
    K163_SIGNATURE * Sig );     // [out] sig

int K163_KAT( void );

