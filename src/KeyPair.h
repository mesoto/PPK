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
