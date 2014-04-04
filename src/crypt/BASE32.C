/**
 * Base32.c
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

#include "base32.h"
#include "sha1.h"

// --------------------------------------------------------------------------
//
// --------------------------------------------------------------------------
unsigned char Base32CharMap[32] = "0123456789ABCDEFGHJKLMNPRSTUWXYZ";

static int Base32BinData( unsigned char ci )
{
    if( ci >= 'a' && ci <= 'z' ) ci -= 'a' - 'A';

    switch( ci )
    {
    case 'O':
    case '0': return 0;
    case 'I':
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': return 10;
    case 'B': return 11;
    case 'C': return 12;
    case 'D': return 13;
    case 'E': return 14;
    case 'F': return 15;
    case 'G': return 16;
    case 'H': return 17;
    case 'J': return 18;
    case 'K': return 19;
    case 'L': return 20;
    case 'M': return 21;
    case 'N': return 22;
    case 'P': return 23;
    case 'R': return 24;
    case 'S': return 25;
    case 'T': return 26;
    case 'U': return 27;
    case 'W': return 28;
    case 'X': return 29;
    case 'Y': return 30;
    case 'Z': return 31;
    }

    return -1;
}

typedef struct
{
    int data;
    int bits;
    unsigned char * pData;

} BASE_STATE, *PBASE_STATE;

unsigned char GetBase32Byte( PBASE_STATE pbs )
{
    unsigned char n;
    while( pbs->bits < 8 )
    {
        pbs->data |= Base32BinData( *(pbs->pData)++ ) << pbs->bits;
        pbs->bits += 5;
    }

    n = (unsigned char)(pbs->data & 0xff);
    pbs->data >>= 8;
    pbs->bits -= 8;

    return n;
}

void PutBase32Byte( PBASE_STATE pbs, unsigned char data )
{
    pbs->data |= data << pbs->bits;
    pbs->bits += 8;

    while( pbs->bits >= 5 )
    {
        *(pbs->pData)++ = Base32CharMap[pbs->data & 0x1F];
        pbs->data >>= 5;
        pbs->bits -= 5;
    }
}

// --------------------------------------------------------------------------
//
// --------------------------------------------------------------------------
unsigned long  DecodeBase32Block(
    unsigned char * Base32Data,                 // [in]
    unsigned long   DataSize,                   // [in]
    unsigned char * BinaryData )                // [out]
{
    unsigned long i;
    BASE_STATE bs = {0};
    unsigned char digest[20];


    bs.pData = Base32Data;

    for( i = 0; i < DataSize; i++ )
    {
        BinaryData[i] = GetBase32Byte( &bs );
        if( bs.data < 0 ) return 0;
    }

    // Check packet integrity

    SHA1_Hash( BinaryData, DataSize, digest );   // Integrity check

    if( (Base32BinData( bs.pData[0] ) != (digest[0] & 0x1F)) ||
        (Base32BinData( bs.pData[1] ) != (digest[1] & 0x1F)) ) return 0;

    return DataSize;
}

// --------------------------------------------------------------------------
//
// --------------------------------------------------------------------------
unsigned long  CreateBase32Block(
    unsigned char * BinaryData,                 // [in]
    unsigned long   DataSize,                   // [in]
    unsigned char * Base32Data )                // [out]
{
    unsigned char digest[20];
    BASE_STATE bs = {0};

    bs.pData = Base32Data;

    SHA1_Hash( BinaryData, DataSize, digest );   // Integrity check

    while( DataSize > 0 )
    {
        PutBase32Byte( &bs, *BinaryData++ );
        DataSize--;
    }

    if( bs.bits > 0 )
    {
        bs.bits = 0;    // Make sure only one charater is added
        PutBase32Byte( &bs, 0 );
    }

    // Append the check bytes

    bs.pData[0] = Base32CharMap[digest[0] & 0x1F];
    bs.pData[1] = Base32CharMap[digest[1] & 0x1F];
    bs.pData[2] = 0;      // terminator

    return (unsigned long)(bs.pData - Base32Data + 2);   // return string size
}

