#pragma once
#include "KeyPair.h"
#include "StreamIO.h"

#define PPK_VERSION_MAJ     1
#define PPK_VERSION_MIN     0

typedef struct
{
    unsigned char  Magic[4];
    unsigned char  VersionMajor;
    unsigned char  VersionMinor;
    unsigned char  HeaderSize[2];

} PPK_FILE_HEADER, *PPPK_FILE_HEADER;

typedef struct
{
    unsigned char  KeySig[8];
    unsigned char  PublicKey_X[21];
    unsigned char  PublicKey_Y[21];
    unsigned char  SessionInfo_X[21];
    unsigned char  SessionInfo_Y[21];

} PPK_SESSION_KEY, *PPPK_SESSION_KEY;

#define PPK_MAGIC           0x50504B1A  // PPK

// Tags used by PPK:

#define TAG_FILENAME            0x4E    // Original filename
#define TAG_ENC_FILENAME        0x6E    // Original filename (encrypted)
#define TAG_SESSION_KEY         0x4B     // K163-ECKAS-AES128
#define TAG_SESSION_KEY_M       0x6B    // K163-ECKAS-AES128 (multi-target)
#define TAG_ENCRYPTED_FILE      0x46    // E(file_image, SK)
#define TAG_COMMENTS            0x43    // Comments/instructions
#define TAG_SIGNATURE           0x53    // Signed

// Program return values

#define PPK_SUCCESS                     0
#define PPK_CMD_LINE_ERROR              1
#define PPK_PASSWORD_TOO_SHORT          2
#define PPK_PASSWORD_WEAK               3
#define PPK_FILE_NOT_FOUND_ERROR        4
#define PPK_FILE_INTEGRITY_ERROR        5
#define PPK_OPEN_FILE_ERROR             6
#define PPK_FILE_READ_ERROR             7
#define PPK_KEY_CEATION_ERROR           8
#define PPK_FILE_WRITE_ERROR            9
#define PPK_INVALID_FILE_DATA           10
#define PPK_INVALID_VERSION_ERROR       11
#define PPK_UNKNOWN_TAG                 13
#define PPK_END_OF_FILE_REACHED         14
#define PPK_FILE_ALREDY_EXIST           15
#define PPK_INVALID_KEY_DATA            16

// Completion codes

typedef enum
{
    PPK_SUCCESS_RETURN = 0,
    PPK_OPERATION_CANCELED,
    PPK_FILE1_ERROR,
    PPK_FILE2_ERROR,
    PPK_PASSWORD_NOT_VALID
} PPK_COMP_CODE;

// Callback functions provided in GUI
extern "C" unsigned char * GetPrivateKey( HWND hWnd, unsigned char * ExpectedPublicKey );
extern "C" int SetOutputFilename( unsigned char * default_name, unsigned char * filename );

class PPKFile
{
public:
    PPKFile(void);
    ~PPKFile(void);
    PPK_COMP_CODE EncryptFile( unsigned char * PublicKey, unsigned int Flags );
    PPK_COMP_CODE DecryptFile( unsigned char * pFilePath, unsigned int Flags );

    bool overwriteOutput;
    HWND hWnd;
    HWND hProgress;
    CStreamIO file1;
    CStreamIO file2;

private:
    PPK_COMP_CODE DecryptFileImage( void * pac, unsigned long size );
};
