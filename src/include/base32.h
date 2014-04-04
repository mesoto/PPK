unsigned long  DecodeBase32Block(
    unsigned char * Base32Data,                 // [in]
    unsigned long   DataSize,                   // [in]
    unsigned char * BinaryData );               // [out]

unsigned long  CreateBase32Block(
    unsigned char * BinaryData,                 // [in]
    unsigned long   DataSize,                   // [in]
    unsigned char * Base32Data );               // [out]

