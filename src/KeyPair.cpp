/**
 * KeyPair.cpp
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
#include "KeyPair.h"
#include "PPKFile.h"
#include "resource.h"
extern "C"
{
#include "k163ecc.h"
#include "aes128.h"
#include "sha1.h"
#include "base32.h"
}

extern HINSTANCE hInst;								// current instance

CKeyPair::CKeyPair(void)
{
    type = KEY_TYPE_UNKNOWN;
    paired = FALSE;
}

CKeyPair::~CKeyPair(void)
{
    // Clear sensitive data
    ZeroMemory( &private_key, sizeof(private_key) );
}

void CKeyPair::DeriveKeyFromPassword( unsigned char * password )
{
    SHA_INFO si;
    unsigned long len = (unsigned long)strlen( (const char *)&password[0] );

    SHA1Init( &si );
    SHA1Update( &si, password, len );
    SHA1Final( private_key, &si );

    SHA1Init( &si );
    SHA1Update( &si, private_key, 20 );
    SHA1Update( &si, password, len );
    SHA1Final( &private_key[1], &si );

    private_key[0] &= 7;

    ZeroMemory( &si, sizeof(si) );
}

void CKeyPair::GenerateKeyPair( unsigned char * password )
{
    K163_POINT p;

    DeriveKeyFromPassword( password );

    K163_CalculatePublicKey( private_key, 21, &p );

    memcpy( public_key, p.X, 21 );

    MakeKeyPrintable( p.X, sizeof(p.X), public_key_str );
    paired = TRUE;
    type = KEY_TYPE_OWNED;

    ZeroMemory( &p, sizeof(p) );
}

int CKeyPair::ExtractPublicKey( unsigned char * KeyString )
{
    unsigned char * p, d;
    unsigned long c, n = 0;

    paired = FALSE;
    type = KEY_TYPE_OTHERS;
    p = KeyString;
    while( *p == ' ' ) p++;
    c = (unsigned long)strlen( (const char *)p );
    key_id[0] = 0;

    if( p[0] == '{' && c > 37 && p[37] == '/' )
    {
        // Format: {72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT/key_id}
        n = DecodeBase32Block( p+1, 21, public_key );
        p += 38;
        d = '}';
    }
    else if( p[1] == '\t' && p[38] == '\t' )
    {
        // List box format
        //  P <tab> 72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT <tab> key_id
        type = p[0];
        n = DecodeBase32Block( p+2, 21, public_key );
        p += 39;
        d = '\0';
    }
    else
    {
        // Format .csv:
        //  Tag,72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT,key_id
        //  Tag,72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT,"key_id"
        //  72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT,key_id
        //  72TLFHHS90BWPG6NYRPLEZGTCG3NA79204RT,"key_id"

        if( p[1] == ',' )
        {
            type = p[0];
            p += 2;
        }
        n = DecodeBase32Block( p, 21, public_key );
        p += 36;
        d = '\0';
        while( *p == ' ' ) p++;
        if( *p == ',' || *p == '\t' )
        {
            p++;
            while( *p == ' ' ) p++;
        }
        if( *p == '"' )
        {
            p++;
            d = '"';
        }
    }
    if( n != 21 ) return PPK_INVALID_KEY_DATA;

    for( n = 0; n < (sizeof(key_id) - 1); p++ )
    {
        if( *p == '\0' || *p == d ) break;
        key_id[n++] = *p;
    }
    key_id[n] = 0;

    for( n = 0, c = 0; n < 21; n++ ) c ^= public_key[n];
    if( (c & 0xF8) == 0 )
    {
        public_key[0] &= 7;
        MakeKeyPrintable( public_key, 21, public_key_str );
        return PPK_SUCCESS;
    }

    return PPK_INVALID_KEY_DATA;
}

extern "C" unsigned long MakeKeyPrintable( unsigned char * key, unsigned long size, unsigned char * buffer )
{
    unsigned long i, n;

    // Fill upper 5 bits with parity

    for( i = n = 0; i < size; i++ ) n ^= key[i];
    key[0] ^= (unsigned char)(n & 0xF8);

    n = CreateBase32Block( key, size, buffer );
    key[0] &= 7;
    buffer[n] = 0;

    return n;
}

extern "C" int CheckPasswordStrength( unsigned char * password )
{
    unsigned long i, n, len = (unsigned long)strlen((const char *)&password[0]);

    if( len < 10 ) return PPK_PASSWORD_TOO_SHORT;

    for( i = n = 0; i < len; i++ )
    {
        if( password[i] < 0x20 ) password[i] = '-';
        if( islower(password[i]) ) n |= 1;
        if( isupper(password[i]) ) n |= 2;
        if( isdigit(password[i]) ) n |= 4;
        if( !isalnum(password[i]) ) n |= 8;
    }

    if( n != 15 ) return PPK_PASSWORD_WEAK;

    return PPK_SUCCESS;
}

CKeyFile::CKeyFile(void)
{
    CKeyPair k;
    CHAR buff[300];
    
    // Get the PPK.exe file path
    GetModuleFileName( GetModuleHandle(NULL), (LPSTR)&buff[0], sizeof(buff) );
    GetFullPathName( (LPCSTR)&buff[0], sizeof(full_path), (LPSTR)&full_path[0], (LPSTR *)&file_name );
    strcpy_s( (char *)file_name, 20, "PPKDir.csv" );

    if( IsFilePresent( (char *)&full_path[0] )) return;

    if( GetEnvironmentVariable( "LOCALAPPDATA", (LPSTR)&buff[0], sizeof(buff) ) ||
        GetEnvironmentVariable( "APPDATA", (LPSTR)&buff[0], sizeof(buff) ))
    {
        strcat_s( (char *)&buff[0], sizeof(buff), "\\PPK" );
        if( !IsFilePresent( &buff[0] ))
            CreateDirectory( (LPCSTR)&buff[0], NULL );
        strcat_s( (char *)&buff[0], sizeof(buff), "\\PPKDir.csv" );

        GetFullPathName( (LPCSTR)&buff[0], sizeof(full_path), (LPSTR)&full_path[0], (LPSTR *)&file_name );
        if( IsFilePresent( (char *)&buff[0] )) return;
    }

    LoadString(hInst, IDS_INITIAL_KEY, buff, 80);
    k.ExtractPublicKey( (unsigned char *)&buff[0] );
    k.type = KEY_TYPE_OTHERS;

    if( ReOpen( "wt" ) == PPK_SUCCESS )
    {
        AddNewKey( &k );
        Close();
    }
}

CKeyFile::~CKeyFile(void)
{
}

int CKeyFile::GetFirstKey( CKeyPair * key )
{
    ReOpen( "rt" );
    return GetNextKey(key);
}

int CKeyFile::GetNextKey( CKeyPair * key )
{
    unsigned long n;
    unsigned char buff[100];

    while( 1 )
    {
        n = ReadLine( &buff[0], sizeof(buff)-1 );
        if( error != 0 ) return error;

        if( n < 39 ) continue;

        return key->ExtractPublicKey( (unsigned char *)buff );
    }
}

int CKeyFile::AddNewKey( CKeyPair * key )
{
    fprintf( (FILE *)handle, "%c,%s,\"%s\"\n", 
        key->type, &key->public_key_str[0], &key->key_id[0] );
    return 0;
}
