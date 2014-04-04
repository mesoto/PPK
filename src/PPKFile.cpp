/**
 * PPKFile.cpp
 *
 * Written by: Mehdi Sotoodeh
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "StdAfx.h"
#include <stdio.h>
#include "PPKFile.h"

extern "C"
{
#include "k163ecc.h"
#include "aes128.h"
#include "sha1.h"
#include "base32.h"
}

#ifdef _DBL_TEST
const static unsigned char BdPublicKey[] =
{
    0x01,0x47,0xEF,0x2F,0xA7,0xC3,0xA6,0xA2,0x3B,0x60,0x26,0x5C,0xE7,0xDB,0xEE,0xD9,0xBB,0xFE,0x4D,0x68,0xCF
    //0x01,0x37,0xF7,0xC6,0x45,0xF4,0xC4,0x02,0x72,0x93,0x41,0x69,0x45,0x4A,0xE7,0x10,0x11,0x85,0x5B,0xBB,0x65
};
#endif

static struct
{
    unsigned long tsc_lo;
    unsigned long tsc_hi;
    SYSTEMTIME    sys_time;
    LARGE_INTEGER PerfCounter;
    unsigned char digest[20];
} random_seed;

extern "C" void
GenRandom( unsigned char * pData, unsigned long Size )
{
    int i;

    while( Size > 0 )
    {
        __asm
        {
            rdtsc
            add random_seed.tsc_lo, eax
            add random_seed.tsc_hi, edx
        }

        GetSystemTime( &random_seed.sys_time);
        QueryPerformanceCounter( &random_seed.PerfCounter );

        SHA1_Hash((unsigned char*)&random_seed, sizeof(random_seed), random_seed.digest );
        for( i = 0; i < 20; i++ )
        {
            *pData++ = random_seed.digest[i];
            if( --Size == 0 )
                return;
        }
    }
}

extern "C" unsigned long GetMSBF16( unsigned char * buff )
{
    return ((buff[0] << 8 ) | buff[1] );
}

extern "C" void PutMSBF16( unsigned char * buff, unsigned long value )
{
    buff[0] = (unsigned char)(value >> 8);
    buff[1] = (unsigned char)value;
}

extern "C" unsigned long GetMSBF32( unsigned char * buff )
{
    return ((buff[0] << 24) | (buff[1] << 16) |
            (buff[2] << 8 ) | buff[3] );
}

extern "C" void PutMSBF32( unsigned char * buff, unsigned long value )
{
    buff[0] = (unsigned char)(value >> 24);
    buff[1] = (unsigned char)(value >> 16);
    buff[2] = (unsigned char)(value >> 8);
    buff[3] = (unsigned char)value;
}

#define XOR_16B(d,s) { \
    ((unsigned long *)(d))[0] ^= ((unsigned long *)(s))[0]; \
    ((unsigned long *)(d))[1] ^= ((unsigned long *)(s))[1]; \
    ((unsigned long *)(d))[2] ^= ((unsigned long *)(s))[2]; \
    ((unsigned long *)(d))[3] ^= ((unsigned long *)(s))[3]; }


#define MOV_16B(d,s) { \
    ((unsigned long *)(d))[0] = ((unsigned long *)(s))[0]; \
    ((unsigned long *)(d))[1] = ((unsigned long *)(s))[1]; \
    ((unsigned long *)(d))[2] = ((unsigned long *)(s))[2]; \
    ((unsigned long *)(d))[3] = ((unsigned long *)(s))[3]; }

PPKFile::PPKFile(void)
{
}

PPKFile::~PPKFile(void)
{
}

// file1 = input file to encrypt
// file2 = output encrypted file
// key = public key used for encryption
// Function returns one of the completion codes

PPK_COMP_CODE PPKFile::EncryptFile( unsigned char * PublicKey, unsigned int Flags )
{
    int prog;
    double t;
    unsigned long n, FileSize;
    AES128_CONTEXT SessionKey;
    unsigned char IV[21], SharedKey[16], buff[256];
    PPK_FILE_HEADER h;
    PPK_SESSION_KEY kx;
    SHA_INFO shaInfo;
    //K163_POINT pubkey;

    prog = 0;
    SendMessage(hProgress, PBM_SETPOS, 0, 0); 

    file1.Seek( 0 );
    FileSize = file1.size;

    SHA1Init( &shaInfo );

    // Create file header information

    PutMSBF32( h.Magic, PPK_MAGIC );
    PutMSBF16( h.HeaderSize, sizeof(h) );
    h.VersionMajor = PPK_VERSION_MAJ;
    h.VersionMinor = PPK_VERSION_MIN;

    if( file2.WriteBytes( &h, sizeof(h) ))
        return PPK_FILE2_ERROR;

    // Create a random exchange key and derive a session key from it

    // Call GenRandom few times to collect more entropy

    for( n = 0; n < 20; n++ ) GenRandom( (unsigned char *)&kx, sizeof(kx) );

#ifdef _DEBUG
    //memset( &kx, 0x55, sizeof(kx) );    // debug only
#endif

#ifdef _DBL_TEST
    if( Flags & 0x100 ) // F_DOUBLE_KEY
    {
        K163_CreateSharedKey( (PK163_POINT)&BdPublicKey[0], 0, 
            kx.PublicKey_X, sizeof(kx.PublicKey_X), kx.SessionInfo_Y, SharedKey );
        AES128_LoadKey( &SessionKey, SharedKey );

        K163_CreateSharedKey( (PK163_POINT)&PublicKey[0], 0, kx.PublicKey_Y, sizeof(kx.PublicKey_Y), kx.SessionInfo_X, SharedKey );
        AES128_EncryptBlock( &SessionKey, kx.PublicKey_Y, sizeof(kx.PublicKey_Y) );

    }
#else
    K163_CreateSharedKey( (PK163_POINT)&PublicKey[0], 0, kx.PublicKey_X, sizeof(kx.PublicKey_X), kx.SessionInfo_X, SharedKey );
#endif

    AES128_LoadKey( &SessionKey, SharedKey );
    ZeroMemory( &IV[0], sizeof(IV) );    // Create KeySig = E(0)
    AES128_Encrypt( &SessionKey, IV );
    memcpy( &kx.KeySig[0], IV, sizeof(kx.KeySig) );
    memcpy( &kx.PublicKey_X[0], PublicKey, sizeof(kx.PublicKey_X) );

    // The actual key will be E(kx.PublicKey_Y)

    memcpy( &IV[0], &kx.PublicKey_Y, 16 );
    AES128_Encrypt( &SessionKey, IV );              // Actual encryption key
    AES128_LoadKey( &SessionKey, IV );

    if( file2.WriteTlv( TAG_SESSION_KEY_M, &kx, sizeof(kx) ))
        return PPK_FILE2_ERROR;

    strcpy_s((char *)&buff[0], sizeof(buff), (const char *)file1.file_name);
    n = (unsigned long)strlen((const char *)buff) + 1;  // include terminator 
    AES128_EncryptBlock( &SessionKey, buff, n );
    if( file2.WriteTlv( TAG_ENC_FILENAME, buff, n ))
        return PPK_FILE2_ERROR;

    ZeroMemory( &IV[0], sizeof(IV) );      // IV=0

    // Format: file_data[n] + pad[0-15] + last_record_size[1] + mac[16]

    if( file2.WriteTlvHead( TAG_ENCRYPTED_FILE, (FileSize + 32) & ~15 )) 
        return PPK_FILE2_ERROR;

    while( FileSize > 15 )
    {
        if( file1.ReadBytes( buff, 16 )) return PPK_FILE1_ERROR;

        SHA1Update( &shaInfo, buff, 16 );

        // Encrypt the file using CBC

        XOR_16B( IV, buff );
        AES128_Decrypt( &SessionKey, IV );

        // Write buff to file

        if( file2.WriteBytes( IV, 16 )) return PPK_FILE2_ERROR;

        FileSize -= 16;

        t = ((double)file1.offset/(double)file1.size) * 100.0;
        if( prog != (int)t )
        {
            prog = (int)t;
            SendMessage(hProgress, PBM_SETPOS, (WPARAM)prog, 0); 
        }
    }

    if( FileSize > 0 )
    {
        if( file1.ReadBytes( buff, FileSize )) return PPK_FILE1_ERROR;
        SHA1Update( &shaInfo, buff, FileSize );
    }

    // Write the final hash
    SHA1Final( buff+16, &shaInfo );

    buff[15] = (unsigned char)FileSize;
    while( FileSize < 15 ) buff[FileSize++] = 0;

    XOR_16B( buff, IV );
    AES128_Decrypt( &SessionKey, buff );
    AES128_Encrypt( &SessionKey, buff+16 );   // E(Hash(file))

    if( file2.WriteBytes( buff, 32 )) return PPK_FILE2_ERROR;

    SendMessage(hProgress, PBM_SETPOS, (WPARAM)100, 0); 
    return PPK_SUCCESS_RETURN;
}

// Function returns one of the completion codes

PPK_COMP_CODE PPKFile::DecryptFileImage( void * pac, unsigned long size )
{
    double t;
    unsigned long n, nRead, FileSize;
    unsigned char IV[16],Temp[16], Buffer[0x4000];
    unsigned char * p;
    SHA_INFO      shaInfo;

    SHA1Init( &shaInfo );

    FileSize = size - 32;
    ZeroMemory( IV, 16 );

    while( FileSize > 0 )
    {
        nRead = (FileSize > sizeof(Buffer)) ? sizeof(Buffer) : FileSize;

        if( file1.ReadBytes( Buffer, nRead )) return PPK_FILE1_ERROR;
       
        p = Buffer + nRead - 16;
        MOV_16B( Temp, p );

        // Decrypt the file

        for( n = nRead >> 4; n > 1; n-- )
        {
            AES128_Encrypt( (PAES128_CONTEXT)pac, p );
            XOR_16B( p, p-16 );
            p -= 16;
        }

        t = (double)file1.offset/(double)file1.size;
        SendMessage(hProgress, PBM_SETPOS, (WPARAM)(int)(t*100), 0); 

        AES128_Encrypt( (PAES128_CONTEXT)pac, p );
        XOR_16B( p, IV );
        MOV_16B( IV, Temp );

        FileSize -= nRead;
        if( file2.WriteBytes( Buffer, nRead ))
            return PPK_FILE2_ERROR;

        SHA1Update( &shaInfo, Buffer, nRead );
    }

    // Process last two blocks

    if( file1.ReadBytes( Buffer, 32 )) return PPK_FILE1_ERROR;

    AES128_Encrypt( (PAES128_CONTEXT)pac, Buffer );
    XOR_16B( Buffer, IV );

    if( Buffer[15] > 15 )   // remaining byte of file
        goto file_integrity_error;

    for( n = Buffer[15]; n < 15; n++ )
        if( Buffer[n] != 0 ) goto file_integrity_error;

    if( Buffer[15] > 0 )
    {
        if( file2.WriteBytes( Buffer, Buffer[15] ))
            return PPK_FILE2_ERROR;

        SHA1Update( &shaInfo, Buffer, Buffer[15] );
    }

    // Check file hash for its integriry

    SHA1Final( Buffer+32, &shaInfo );
    AES128_Encrypt( (PAES128_CONTEXT)pac, Buffer+32 );

    SendMessage(hProgress, PBM_SETPOS, (WPARAM)100, 0); 

    if( memcmp( Buffer+16, Buffer+32, 16) != 0 ) 
    {
        file_integrity_error:
        file1.SetError( PPK_FILE_INTEGRITY_ERROR );
        return PPK_FILE1_ERROR;
    }

    return PPK_SUCCESS_RETURN;
}

// Function returns one of the completion codes

PPK_COMP_CODE PPKFile::DecryptFile( unsigned char * pFilePath, unsigned int Flags )
{
    PPK_COMP_CODE rc;
    unsigned long len;
    PPK_FILE_HEADER h = {0};
    AES128_CONTEXT SessionKey;
    unsigned char tag, buff[260];

    if( file1.ReadBytes( &h, sizeof(h) ))
    {
        file1.Close();
        return PPK_FILE1_ERROR;
    }

    if( GetMSBF32(h.Magic) != PPK_MAGIC )
    {
        file1.SetError( PPK_INVALID_FILE_DATA );
        return PPK_FILE1_ERROR;
    }

    if( h.VersionMajor > PPK_VERSION_MAJ )
    {
        file1.error_info = (h.VersionMajor<<8)+h.VersionMinor;
        file1.SetError( PPK_INVALID_VERSION_ERROR );
        return PPK_FILE1_ERROR;
    }

    file1.Seek( GetMSBF16(h.HeaderSize) );

    // Information from this point on is TLV based.

    while( file1.offset < file1.size )
    {
        tag = file1.ReadByte();     // Tag
        len = file1.GetTlvLength();

        switch( tag )
        {
        case TAG_SESSION_KEY:
        case TAG_SESSION_KEY_M:
            if( len == sizeof(PPK_SESSION_KEY) )
            {
                PPK_SESSION_KEY kx;
                unsigned char * private_key;

                file1.ReadBytes( &kx, len );

                MakeKeyPrintable( kx.PublicKey_X, sizeof(kx.PublicKey_X), buff );
                private_key = GetPrivateKey( hWnd, buff );
                if( private_key == NULL )
                {
                    return PPK_OPERATION_CANCELED;
                }

                K163_XOnlyMultiply( kx.SessionInfo_X, private_key, 21, buff );

                AES128_LoadKey( &SessionKey, buff+2 );

                // Do we get correct response?

                ZeroMemory( buff, sizeof(buff) );
                AES128_Encrypt( &SessionKey, buff );
                if( memcmp( buff, kx.KeySig, sizeof(kx.KeySig) ) != 0 )
                {
                    return PPK_PASSWORD_NOT_VALID;
                }

                if( tag == TAG_SESSION_KEY_M )
                {
                    // The actual key will be E(kx.PublicKey_Y)

                    AES128_Encrypt( &SessionKey, kx.PublicKey_Y );
                    AES128_LoadKey( &SessionKey, kx.PublicKey_Y );
                }
                else
                {
                    // The actual key will be E(E(0))

                    AES128_Encrypt( &SessionKey, buff );
                    AES128_LoadKey( &SessionKey, buff );
                }
                ZeroMemory( (char *)&kx, sizeof(kx) );
                ZeroMemory( (char *)&buff[0], sizeof(buff) );
                continue;
            }
            break;

        case TAG_FILENAME:  // Original file name
        case TAG_ENC_FILENAME:  // Original file name (encrypted)
            if( len < sizeof(buff) && file1.ReadBytes( buff, len ) == 0 )
            {
                if( tag == TAG_ENC_FILENAME )
                    AES128_DecryptBlock( &SessionKey, buff, len );

                if( buff[len-1] != 0 ) break;
                if( Flags & 1 ) continue;

                if( SetOutputFilename( pFilePath, &buff[0] ) == PPK_SUCCESS ) continue;

                return PPK_FILE2_ERROR;
            }
            break;

        case TAG_ENCRYPTED_FILE:
            if( len >= 32 && (len & 15) == 0 )
            {
                if( file2.handle == NULL )
                {
                    if( SetOutputFilename( pFilePath, NULL ) != PPK_SUCCESS ) return PPK_FILE2_ERROR;
                }

                rc = DecryptFileImage( &SessionKey, len );
                file2.Close();

                if( rc == 0 ) continue;

                return rc;
            }
            break;

        default:
            file1.SetError( PPK_UNKNOWN_TAG );
            return PPK_FILE1_ERROR;
        }

        file1.SetError( PPK_INVALID_FILE_DATA );
        return PPK_FILE1_ERROR;
    }

    return PPK_SUCCESS_RETURN;
}

