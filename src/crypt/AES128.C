/**
 * AES-128    Written by: Mehdi Sotoodeh
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


#include <memory.h>
#include "aes128.h"

static unsigned char S_BOX[256] = 
{
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static unsigned char S_BOX_Inv[256] = 
{
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static unsigned char mul_by_2[256] = 
{ 
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

static unsigned char mul_by_4[256] = 
{ 
    0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,
    0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,
    0x80,0x84,0x88,0x8c,0x90,0x94,0x98,0x9c,0xa0,0xa4,0xa8,0xac,0xb0,0xb4,0xb8,0xbc,
    0xc0,0xc4,0xc8,0xcc,0xd0,0xd4,0xd8,0xdc,0xe0,0xe4,0xe8,0xec,0xf0,0xf4,0xf8,0xfc,
    0x1b,0x1f,0x13,0x17,0x0b,0x0f,0x03,0x07,0x3b,0x3f,0x33,0x37,0x2b,0x2f,0x23,0x27,
    0x5b,0x5f,0x53,0x57,0x4b,0x4f,0x43,0x47,0x7b,0x7f,0x73,0x77,0x6b,0x6f,0x63,0x67,
    0x9b,0x9f,0x93,0x97,0x8b,0x8f,0x83,0x87,0xbb,0xbf,0xb3,0xb7,0xab,0xaf,0xa3,0xa7,
    0xdb,0xdf,0xd3,0xd7,0xcb,0xcf,0xc3,0xc7,0xfb,0xff,0xf3,0xf7,0xeb,0xef,0xe3,0xe7,
    0x36,0x32,0x3e,0x3a,0x26,0x22,0x2e,0x2a,0x16,0x12,0x1e,0x1a,0x06,0x02,0x0e,0x0a,
    0x76,0x72,0x7e,0x7a,0x66,0x62,0x6e,0x6a,0x56,0x52,0x5e,0x5a,0x46,0x42,0x4e,0x4a,
    0xb6,0xb2,0xbe,0xba,0xa6,0xa2,0xae,0xaa,0x96,0x92,0x9e,0x9a,0x86,0x82,0x8e,0x8a,
    0xf6,0xf2,0xfe,0xfa,0xe6,0xe2,0xee,0xea,0xd6,0xd2,0xde,0xda,0xc6,0xc2,0xce,0xca,
    0x2d,0x29,0x25,0x21,0x3d,0x39,0x35,0x31,0x0d,0x09,0x05,0x01,0x1d,0x19,0x15,0x11,
    0x6d,0x69,0x65,0x61,0x7d,0x79,0x75,0x71,0x4d,0x49,0x45,0x41,0x5d,0x59,0x55,0x51,
    0xad,0xa9,0xa5,0xa1,0xbd,0xb9,0xb5,0xb1,0x8d,0x89,0x85,0x81,0x9d,0x99,0x95,0x91,
    0xed,0xe9,0xe5,0xe1,0xfd,0xf9,0xf5,0xf1,0xcd,0xc9,0xc5,0xc1,0xdd,0xd9,0xd5,0xd1
};

static unsigned char mul_by_6[256] = 
{ 
    0x00,0x06,0x0c,0x0a,0x18,0x1e,0x14,0x12,0x30,0x36,0x3c,0x3a,0x28,0x2e,0x24,0x22,
    0x60,0x66,0x6c,0x6a,0x78,0x7e,0x74,0x72,0x50,0x56,0x5c,0x5a,0x48,0x4e,0x44,0x42,
    0xc0,0xc6,0xcc,0xca,0xd8,0xde,0xd4,0xd2,0xf0,0xf6,0xfc,0xfa,0xe8,0xee,0xe4,0xe2,
    0xa0,0xa6,0xac,0xaa,0xb8,0xbe,0xb4,0xb2,0x90,0x96,0x9c,0x9a,0x88,0x8e,0x84,0x82,
    0x9b,0x9d,0x97,0x91,0x83,0x85,0x8f,0x89,0xab,0xad,0xa7,0xa1,0xb3,0xb5,0xbf,0xb9,
    0xfb,0xfd,0xf7,0xf1,0xe3,0xe5,0xef,0xe9,0xcb,0xcd,0xc7,0xc1,0xd3,0xd5,0xdf,0xd9,
    0x5b,0x5d,0x57,0x51,0x43,0x45,0x4f,0x49,0x6b,0x6d,0x67,0x61,0x73,0x75,0x7f,0x79,
    0x3b,0x3d,0x37,0x31,0x23,0x25,0x2f,0x29,0x0b,0x0d,0x07,0x01,0x13,0x15,0x1f,0x19,
    0x2d,0x2b,0x21,0x27,0x35,0x33,0x39,0x3f,0x1d,0x1b,0x11,0x17,0x05,0x03,0x09,0x0f,
    0x4d,0x4b,0x41,0x47,0x55,0x53,0x59,0x5f,0x7d,0x7b,0x71,0x77,0x65,0x63,0x69,0x6f,
    0xed,0xeb,0xe1,0xe7,0xf5,0xf3,0xf9,0xff,0xdd,0xdb,0xd1,0xd7,0xc5,0xc3,0xc9,0xcf,
    0x8d,0x8b,0x81,0x87,0x95,0x93,0x99,0x9f,0xbd,0xbb,0xb1,0xb7,0xa5,0xa3,0xa9,0xaf,
    0xb6,0xb0,0xba,0xbc,0xae,0xa8,0xa2,0xa4,0x86,0x80,0x8a,0x8c,0x9e,0x98,0x92,0x94,
    0xd6,0xd0,0xda,0xdc,0xce,0xc8,0xc2,0xc4,0xe6,0xe0,0xea,0xec,0xfe,0xf8,0xf2,0xf4,
    0x76,0x70,0x7a,0x7c,0x6e,0x68,0x62,0x64,0x46,0x40,0x4a,0x4c,0x5e,0x58,0x52,0x54,
    0x16,0x10,0x1a,0x1c,0x0e,0x08,0x02,0x04,0x26,0x20,0x2a,0x2c,0x3e,0x38,0x32,0x34
};

static unsigned char mul_by_15[256] = 
{ 
    0x00,0x0f,0x1e,0x11,0x3c,0x33,0x22,0x2d,0x78,0x77,0x66,0x69,0x44,0x4b,0x5a,0x55,
    0xf0,0xff,0xee,0xe1,0xcc,0xc3,0xd2,0xdd,0x88,0x87,0x96,0x99,0xb4,0xbb,0xaa,0xa5,
    0xfb,0xf4,0xe5,0xea,0xc7,0xc8,0xd9,0xd6,0x83,0x8c,0x9d,0x92,0xbf,0xb0,0xa1,0xae,
    0x0b,0x04,0x15,0x1a,0x37,0x38,0x29,0x26,0x73,0x7c,0x6d,0x62,0x4f,0x40,0x51,0x5e,
    0xed,0xe2,0xf3,0xfc,0xd1,0xde,0xcf,0xc0,0x95,0x9a,0x8b,0x84,0xa9,0xa6,0xb7,0xb8,
    0x1d,0x12,0x03,0x0c,0x21,0x2e,0x3f,0x30,0x65,0x6a,0x7b,0x74,0x59,0x56,0x47,0x48,
    0x16,0x19,0x08,0x07,0x2a,0x25,0x34,0x3b,0x6e,0x61,0x70,0x7f,0x52,0x5d,0x4c,0x43,
    0xe6,0xe9,0xf8,0xf7,0xda,0xd5,0xc4,0xcb,0x9e,0x91,0x80,0x8f,0xa2,0xad,0xbc,0xb3,
    0xc1,0xce,0xdf,0xd0,0xfd,0xf2,0xe3,0xec,0xb9,0xb6,0xa7,0xa8,0x85,0x8a,0x9b,0x94,
    0x31,0x3e,0x2f,0x20,0x0d,0x02,0x13,0x1c,0x49,0x46,0x57,0x58,0x75,0x7a,0x6b,0x64,
    0x3a,0x35,0x24,0x2b,0x06,0x09,0x18,0x17,0x42,0x4d,0x5c,0x53,0x7e,0x71,0x60,0x6f,
    0xca,0xc5,0xd4,0xdb,0xf6,0xf9,0xe8,0xe7,0xb2,0xbd,0xac,0xa3,0x8e,0x81,0x90,0x9f,
    0x2c,0x23,0x32,0x3d,0x10,0x1f,0x0e,0x01,0x54,0x5b,0x4a,0x45,0x68,0x67,0x76,0x79,
    0xdc,0xd3,0xc2,0xcd,0xe0,0xef,0xfe,0xf1,0xa4,0xab,0xba,0xb5,0x98,0x97,0x86,0x89,
    0xd7,0xd8,0xc9,0xc6,0xeb,0xe4,0xf5,0xfa,0xaf,0xa0,0xb1,0xbe,0x93,0x9c,0x8d,0x82,
    0x27,0x28,0x39,0x36,0x1b,0x14,0x05,0x0a,0x5f,0x50,0x41,0x4e,0x63,0x6c,0x7d,0x72
};

static unsigned long round_const[10] = 
{ 
    0x01,0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

#define x00 0
#define x10 1
#define x20 2
#define x30 3
#define x01 4
#define x11 5
#define x21 6
#define x31 7
#define x02 8
#define x12 9
#define x22 10
#define x32 11
#define x03 12
#define x13 13
#define x23 14
#define x33 15

/* Exor corresponding text input and round key input bytes */

static void KeyAddition( unsigned char * d, unsigned char * key ) 
{
    ((unsigned long *)d)[0] ^= ((unsigned long *)key)[0];
    ((unsigned long *)d)[1] ^= ((unsigned long *)key)[1];
    ((unsigned long *)d)[2] ^= ((unsigned long *)key)[2];
    ((unsigned long *)d)[3] ^= ((unsigned long *)key)[3];
}

static void SubstituteShiftRow( unsigned char * d, unsigned char * s )
{
    d[x00] = S_BOX[s[x00]]; d[x01] = S_BOX[s[x01]];
    d[x02] = S_BOX[s[x02]]; d[x03] = S_BOX[s[x03]];

    d[x13] = S_BOX[s[x10]]; d[x10] = S_BOX[s[x11]];
    d[x11] = S_BOX[s[x12]]; d[x12] = S_BOX[s[x13]];

    d[x22] = S_BOX[s[x20]]; d[x20] = S_BOX[s[x22]];
    d[x23] = S_BOX[s[x21]]; d[x21] = S_BOX[s[x23]];

    d[x31] = S_BOX[s[x30]]; d[x30] = S_BOX[s[x33]];
    d[x33] = S_BOX[s[x32]]; d[x32] = S_BOX[s[x31]];
}

static void InvSubstituteShiftRow( unsigned char * d, unsigned char * s )
{
    d[x00] = S_BOX_Inv[s[x00]]; d[x01] = S_BOX_Inv[s[x01]];
    d[x02] = S_BOX_Inv[s[x02]]; d[x03] = S_BOX_Inv[s[x03]];

    d[x11] = S_BOX_Inv[s[x10]]; d[x10] = S_BOX_Inv[s[x13]];
    d[x13] = S_BOX_Inv[s[x12]]; d[x12] = S_BOX_Inv[s[x11]];

    d[x22] = S_BOX_Inv[s[x20]]; d[x20] = S_BOX_Inv[s[x22]];
    d[x23] = S_BOX_Inv[s[x21]]; d[x21] = S_BOX_Inv[s[x23]];

    d[x33] = S_BOX_Inv[s[x30]]; d[x30] = S_BOX_Inv[s[x31]];
    d[x31] = S_BOX_Inv[s[x32]]; d[x32] = S_BOX_Inv[s[x33]];
}

/* Mix the four bytes of every column in a linear way */

#define MixCol(d0,d1,d2,d3) { \
    u2 = d0 ^ d1 ^ d2 ^ d3; \
    u0 = mul_by_2[d0] ^ u2; \
    u2 ^= mul_by_2[d2]; \
    u1 = mul_by_2[d1]; \
    u3 = mul_by_2[d3]; \
    d0 ^= u0 ^ u1; \
    d1 ^= u1 ^ u2; \
    d2 ^= u2 ^ u3; \
    d3 ^= u0 ^ u3; }

static void MixColumn(unsigned char * d)
{
    unsigned char u0, u1, u2, u3;

    MixCol(d[x00],d[x10],d[x20],d[x30]);
    MixCol(d[x01],d[x11],d[x21],d[x31]);
    MixCol(d[x02],d[x12],d[x22],d[x32]);
    MixCol(d[x03],d[x13],d[x23],d[x33]);
}

/* Mix the four bytes of every column in a linear way
 * This is the opposite operation of MixColumn
 */
#define InvMixCol(d0,d1,d2,d3) { \
    u3 = mul_by_15[d0 ^ d1 ^ d2 ^ d3]; \
    u0 = u3 ^ mul_by_2[d2] ^ mul_by_4[d1] ^ mul_by_6[d3]; \
    u1 = u3 ^ mul_by_2[d3] ^ mul_by_4[d2] ^ mul_by_6[d0]; \
    u2 = u3 ^ mul_by_2[d0] ^ mul_by_4[d3] ^ mul_by_6[d1]; \
    d3 ^= u3 ^ mul_by_2[d1] ^ mul_by_4[d0] ^ mul_by_6[d2]; \
    d0 ^= u0; \
    d1 ^= u1; \
    d2 ^= u2; }

static void InvMixColumn(unsigned char * d)
{
    unsigned char u0, u1, u2, u3;

    InvMixCol(d[x00],d[x10],d[x20],d[x30]);
    InvMixCol(d[x01],d[x11],d[x21],d[x31]);
    InvMixCol(d[x02],d[x12],d[x22],d[x32]);
    InvMixCol(d[x03],d[x13],d[x23],d[x33]);
}

typedef union
{
    unsigned char b[16];
    unsigned long l[4];
} MIXED_T;

void AES128_LoadKey(
    PAES128_CONTEXT ac,
    unsigned char * key )
{
    int i;
    MIXED_T tk;
    MIXED_T * pac = (MIXED_T *)&ac->round_key;

    pac->l[0] = tk.l[0] = ((unsigned long *)key)[0];
    pac->l[1] = tk.l[1] = ((unsigned long *)key)[1];
    pac->l[2] = tk.l[2] = ((unsigned long *)key)[2];
    pac->l[3] = tk.l[3] = ((unsigned long *)key)[3];

    for( i = 0; i < 10; i++ )
    {
        pac++;

        tk.b[x00] ^= S_BOX[tk.b[x13]] ^ round_const[i];
        tk.b[x10] ^= S_BOX[tk.b[x23]];
        tk.b[x20] ^= S_BOX[tk.b[x33]];
        tk.b[x30] ^= S_BOX[tk.b[x03]];

        tk.l[1] ^= tk.l[0];
        tk.l[2] ^= tk.l[1];
        tk.l[3] ^= tk.l[2];

        pac->l[0] = tk.l[0];
        pac->l[1] = tk.l[1];
        pac->l[2] = tk.l[2];
        pac->l[3] = tk.l[3];
    }
}

void AES128_Encrypt(
    PAES128_CONTEXT ac,
    unsigned char * data )
{
    unsigned char Temp[16];

    KeyAddition( data, &ac->round_key[0] ); 

    SubstituteShiftRow( Temp, data );
    MixColumn( Temp );
    KeyAddition( Temp, &ac->round_key[1*16] );

    SubstituteShiftRow( data, Temp );
    MixColumn( data );
    KeyAddition( data, &ac->round_key[2*16] );

    SubstituteShiftRow( Temp, data );
    MixColumn( Temp );
    KeyAddition( Temp, &ac->round_key[3*16] );

    SubstituteShiftRow( data, Temp );
    MixColumn( data );
    KeyAddition( data, &ac->round_key[4*16] );

    SubstituteShiftRow( Temp, data );
    MixColumn( Temp );
    KeyAddition( Temp, &ac->round_key[5*16] );

    SubstituteShiftRow( data, Temp );
    MixColumn( data );
    KeyAddition( data, &ac->round_key[6*16] );

    SubstituteShiftRow( Temp, data );
    MixColumn( Temp );
    KeyAddition( Temp, &ac->round_key[7*16] );

    SubstituteShiftRow( data, Temp );
    MixColumn( data );
    KeyAddition( data, &ac->round_key[8*16] );

    SubstituteShiftRow( Temp, data );
    MixColumn( Temp );
    KeyAddition( Temp, &ac->round_key[9*16] );

    SubstituteShiftRow( data, Temp );
    KeyAddition( data, &ac->round_key[10*16] );
}   

void AES128_Decrypt(
    PAES128_CONTEXT ac,
    unsigned char * data )
{
    unsigned char Temp[16];

    KeyAddition( data, &ac->round_key[10*16] ); 
    InvSubstituteShiftRow( Temp, data );

    KeyAddition( Temp, &ac->round_key[9*16] );
    InvMixColumn( Temp );
    InvSubstituteShiftRow( data, Temp );

    KeyAddition( data, &ac->round_key[8*16] );
    InvMixColumn( data );
    InvSubstituteShiftRow( Temp, data );

    KeyAddition( Temp, &ac->round_key[7*16] );
    InvMixColumn( Temp );
    InvSubstituteShiftRow( data, Temp );

    KeyAddition( data, &ac->round_key[6*16] );
    InvMixColumn( data );
    InvSubstituteShiftRow( Temp, data );

    KeyAddition( Temp, &ac->round_key[5*16] );
    InvMixColumn( Temp );
    InvSubstituteShiftRow( data, Temp );

    KeyAddition( data, &ac->round_key[4*16] );
    InvMixColumn( data );
    InvSubstituteShiftRow( Temp, data );

    KeyAddition( Temp, &ac->round_key[3*16] );
    InvMixColumn( Temp );
    InvSubstituteShiftRow( data, Temp );

    KeyAddition( data, &ac->round_key[2*16] );
    InvMixColumn( data );
    InvSubstituteShiftRow( Temp, data );

    KeyAddition( Temp, &ac->round_key[1*16] );
    InvMixColumn( Temp );
    InvSubstituteShiftRow( data, Temp );

    KeyAddition( data, &ac->round_key[0] );
}

void AES128_EncryptBlock(
    PAES128_CONTEXT ac,
    unsigned char * pData,
    unsigned long   Size )
{
    if( Size < 16 )
    {
        unsigned char d[16];
        memset( d, Size, 16 );
        AES128_Encrypt( ac, d );
        while( Size > 0 ) { Size--; pData[Size] ^= d[Size]; }
        return;
    }

    while( Size > 16 )
    {
        AES128_Encrypt( ac, pData );
        pData += 12;
        Size -= 12;
    } 

    AES128_Encrypt( ac, pData + Size - 16 );
}

void AES128_DecryptBlock(
    PAES128_CONTEXT ac,
    unsigned char * pData,
    unsigned long   Size )
{
    unsigned long n;

    if( Size < 16 )
    {
        unsigned char d[16];
        memset( d, Size, 16 );
        AES128_Encrypt( ac, d );
        while( Size > 0 ) { Size--; pData[Size] ^= d[Size]; }
        return;
    }

    n = (Size - 4) % 12;
    if( n > 0 )
    {
        AES128_Decrypt( ac, pData + Size - 16 );
        Size -= n;
    }

    while( Size >= 16 )
    {
        AES128_Decrypt( ac, pData + Size - 16 );
        Size -= 12;
    }
}
