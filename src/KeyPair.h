#pragma once

#include "streamio.h"

#define MAX_PW_LENGTH       40
#define MAX_ID_LENGTH       30
#define PUB_KEY_FMT         "{%s/%s}"
#define KEY_TYPE_OTHERS     'P'     // Created by others
#define KEY_TYPE_OWNED      'V'     // Created by you
#define KEY_TYPE_UNKNOWN    'U'     // Unknown

class CKeyPair
{
public:
    CKeyPair(void);
    ~CKeyPair(void);
    int ExtractPublicKey( unsigned char * KeyString );
    void GenerateKeyPair( unsigned char * password );
    void DeriveKeyFromPassword( unsigned char * Password );

    unsigned char type;
    unsigned char paired;               // true if public & private are paired
    unsigned char public_key[21];
    unsigned char private_key[21];
    unsigned char public_key_str[40];
    unsigned char key_id[MAX_ID_LENGTH+1];

};

class CKeyFile : public CStreamIO
{
public:
    CKeyFile(void);
    ~CKeyFile(void);

    int GetFirstKey( CKeyPair * key );
    int GetNextKey( CKeyPair * key );
    int AddNewKey( CKeyPair * key );
};

extern "C" unsigned long MakeKeyPrintable( unsigned char * key, unsigned long size, unsigned char * buffer );
extern "C" int CheckPasswordStrength( unsigned char * password );
