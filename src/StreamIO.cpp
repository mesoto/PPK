/**
 * StreamIO.cpp
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
#include "PPKFile.h"

CStreamIO::CStreamIO(void)
{
    handle = NULL;
    error_msg[0] = 0;
    error = 0;
}

CStreamIO::~CStreamIO(void)
{
    Close();
}

int CStreamIO::Open( char * name, char * mode )
{
    GetFullPathName( name, sizeof(full_path), (LPSTR)full_path, (LPSTR*)&file_name );
    return ReOpen( mode );
}

int CStreamIO::ReOpen( char * mode )
{
    Close();

    error_msg[0] = 0;
    error = 0;
    if( fopen_s( (FILE**)&handle, (const char *)&full_path[0], mode ))
    {
        return SetError( PPK_OPEN_FILE_ERROR );
    }

    if( mode[0] == 'r' )
    {
        fseek( (FILE*)handle, 0, SEEK_END );
        size = ftell( (FILE*)handle );
        fseek( (FILE*)handle, 0, SEEK_SET );
    }
    offset = 0;
    return 0;
}

void CStreamIO::Close( void ) 
{ 
    if( handle != NULL )
    {
        fclose( (FILE*)handle );
        handle = NULL;
    }
}

void CStreamIO::Seek( unsigned long offset )
{
    fseek( (FILE*)handle, offset, SEEK_SET );
    offset = offset;
}

unsigned char CStreamIO::ReadByte( void )
{
    int r;

    if( error ) return 0;

    r = fgetc( (FILE*)handle );
    if( r == EOF )
    {
        SetError( PPK_FILE_READ_ERROR );
        return 0;
    }
    offset++;
    return (unsigned char)r;
}

unsigned long CStreamIO::GetTlvLength( void )
{
    unsigned long n;
    unsigned char m;
    n = 0;
    do
    {
        m = ReadByte();
        n = (n << 7) | (m & 0x7f);

    } while( m & 0x80 );
    return n;
}

unsigned long CStreamIO::ReadLine( unsigned char * data, unsigned long size )
{
    if( fgets( (char *)data, (int)size, (FILE*)handle ) == NULL )
    {
        SetError( feof((FILE*)handle) ?
            PPK_END_OF_FILE_REACHED : PPK_FILE_READ_ERROR );
        return 0;
    }

    offset = ftell( (FILE*)handle );
    return (unsigned long)strlen( (const char *)data );
}

int CStreamIO::ReadBytes( void * data, unsigned long size )
{
    if( fread( data, sizeof(char), (size_t)size, (FILE*)handle ) != size )
        return SetError( PPK_FILE_READ_ERROR );

    offset += size;
    return 0;
}


int CStreamIO::WriteBytes( void * data, unsigned long size )
{
    if( error == 0 )
    {
        if( fwrite( data, sizeof(char), (size_t)size, (FILE*)handle ) != size ) 
            SetError( PPK_FILE_WRITE_ERROR );
    }
    return error;
}

int CStreamIO::WriteTlvHead( unsigned char tag, unsigned long size )
{
    unsigned char buff[8];
    unsigned long i;

    buff[7] = (unsigned char)(size & 0x7f);
    for( i = 6; size > 0x7f; )
    {
        size >>= 7;
        buff[i--] = (unsigned char)(size | 0x80);
    }

    buff[i] = tag;
    WriteBytes( buff+i, 8-i );
    return error;
}

int CStreamIO::WriteTlv( unsigned char tag, void * data, unsigned long size )
{
    WriteTlvHead( tag, size );
    WriteBytes( data, size );

    return error;
}

int CStreamIO::SetError( int rc )
{
    error = rc;
    switch( rc )
    {
    case PPK_OPEN_FILE_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "Error openning: %s", &file_name[0] ); 
        break;
    case PPK_FILE_NOT_FOUND_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "Could not find: %s", &file_name[0] ); 
        break;
    case PPK_FILE_READ_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "Error reading: %s", &file_name[0] ); 
        break;
    case PPK_FILE_WRITE_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "Error writing: %s", &file_name[0] ); 
        break;

    case PPK_FILE_INTEGRITY_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "File integrity error: %s", &file_name[0] ); 
        break;

    case PPK_UNKNOWN_TAG:
    case PPK_INVALID_FILE_DATA:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "File contains invalid data: %s", &file_name[0] ); 
        break;

    case PPK_INVALID_VERSION_ERROR:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "File encrypted by PPK version %d.%d.\nPPK update needed.", 
            error_info >> 8, error_info & 0xff ); 
        break;

    case PPK_FILE_ALREDY_EXIST:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "File currently exist: %s", &file_name[0] ); 
        break;

    default:
        sprintf_s( (char *)&error_msg[0], sizeof(error_msg), 
            "Unknown error code %d.", rc ); 
        break;
    }
    return rc;
}

extern "C" int IsFilePresent( char * filename )
{
    HANDLE hFind;
    WIN32_FIND_DATA FindFileData;
    hFind = FindFirstFile( (LPCSTR)filename, &FindFileData );
    if( hFind == INVALID_HANDLE_VALUE ) return 0;
    FindClose( hFind );
    return 1;
}