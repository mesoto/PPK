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



