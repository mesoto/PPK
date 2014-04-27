/**
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
#pragma once

class CStreamIO
{
public:

    CStreamIO(void);
    ~CStreamIO(void);
    int Open( char * name, char * mode );
    int ReOpen( char * mode );
    void Close( void );
    void Seek( unsigned long offset );
    unsigned char ReadByte( void );
    unsigned long GetTlvLength( void );
    int ReadBytes( void * data, unsigned long size );
    unsigned long ReadLine( unsigned char * data, unsigned long size );
    int WriteBytes( void * data, unsigned long size );
    int WriteTlvHead( unsigned char tag, unsigned long size );
    int WriteTlv( unsigned char tag, void * data, unsigned long size );
    int SetError( int rc );

    unsigned long offset;
    unsigned long size;
    int           error;
    unsigned long error_info;
    void          * handle;
    unsigned char * file_name;
    unsigned char full_path[300];
    unsigned char error_msg[400];
};

extern "C" int IsFilePresent( char * filename );



