/**
 * Elliptic curve implementation for K-163
 * Written by: Mehdi Sotoodeh
 *
 * sect163k1:
 *
 *	Curve E: y^2 + xy = x^3 + x^2 + 1
 *
 *	p(t) = t^163 + t^7 + t^6 + t^3 + 1 
 *       = 800000000000000000000000000000000000000C9
 *  Base point:
 *  G_x  = 2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8
 *  G_y  = 289070fb05d38ff58321f2e800536d538ccdaa3d9
 *  Order & cofactor:
 *  n    = 4000000000000000000020108a2e0cc0d99f8a5ef
 *  h    = 2
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

#include <stdio.h>
#include <string.h>
#include "k163ecc.h"

#ifndef X86_ASM
#define USE_C_CODE
#endif

typedef unsigned long ELEMENT;
typedef unsigned long K163_DIGIT;

#define K163_DIGITS    ((163+31)/32)

typedef struct {
    ELEMENT  e[6];
} F2N, * PF2N;

/*  coordinates for a point  */

typedef struct 
{
    F2N  x;
    F2N  y;
} F2N_POINT, * PF2N_POINT;

F2N base_point_order = {4,0,0,0x20108,0xA2E0CC0D,0x99F8A5EF};
F2N_POINT base_point = 
{
    {2,0xFE13C053,0x7BBC11AC,0xAA07D793,0xDE4E6D5E,0x5C94EEE8},
    {2,0x89070FB0,0x5D38FF58,0x321F2E80,0x0536D538,0xCCDAA3D9}
};

K163_POINT K163_BasePoint =
{
    {2,0xFE,0x13,0xC0,0x53,0x7B,0xBC,0x11,0xAC,0xAA,0x07,
       0xD7,0x93,0xDE,0x4E,0x6D,0x5E,0x5C,0x94,0xEE,0xE8},
    {2,0x89,0x07,0x0F,0xB0,0x5D,0x38,0xFF,0x58,0x32,0x1F,
       0x2E,0x80,0x05,0x36,0xD5,0x38,0xCC,0xDA,0xA3,0xD9}
};

unsigned char K163_BasePointOrder[K163_FIELD_BYTES] =
{
     4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
       0x01,0x08,0xA2,0xE0,0xCC,0x0D,0x99,0xF8,0xA5,0xEF
};

int K163_Add( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y, int digits );
int K163_Sub( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y, int digits );
void K163_MontMul( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y );
void K163_BytesToDigits( unsigned char * src, K163_DIGIT * dst );
void K163_DigitsToBytes( K163_DIGIT * src, unsigned char * dst );

void GenRandom( unsigned char * pData, unsigned long Size );

void K163_PolyMul( PF2N c, PF2N a, PF2N b );
void K163_PolyInv( PF2N r, PF2N x );
void K163_F2NZero( PF2N a );
void K163_PointAdd( PF2N_POINT p3, PF2N_POINT p1, PF2N_POINT p2 );
unsigned long GetMSBF32( unsigned char * buff );

void K163_MontInv( K163_DIGIT * y, K163_DIGIT * x );    // y = R/x mod BPO

K163_DIGIT K163_BPO[]    = {0x99F8A5EF,0xA2E0CC0D,0x20108,0,0,4};
K163_DIGIT K163_BPO_M2[] = {0x99F8A5ED,0xA2E0CC0D,0x20108,0,0,4};
K163_DIGIT K163_BPO_R1[] = {
    0xD9F8A5EF,0x3C62A291,0xD749CE05,0xFFFF7FBD,0xFFFFFFFF,3};

K163_DIGIT K163_BPO_R2[] = {
    0xAA63410E,0x089C83FB,0x3B1368AE,0x6A34F505,0x719E20D1,1};

#define K163_BPO_INV     0x68D5290F
unsigned long GetMSBF32( unsigned char * buff );
void PutMSBF32( unsigned char * buff, unsigned long value );


void K163_AssignZero( K163_DIGIT * dst, int size )
{
    int i;
    for( i = 0; i < size; i++ ) dst[i] = 0;
}

void K163_Assign( K163_DIGIT * dst, K163_DIGIT * src, int size )
{
    int i;
    for( i = 0; i < size; i++ ) dst[i] = src[i];
}

// Computes y = b*x.
void K163_DigitMul( K163_DIGIT * y, K163_DIGIT b, K163_DIGIT * x, int digits )
{
    K163_DIGIT carry;
    for(carry = 0; digits > 0; digits--, x++, y++)
    {
#ifdef USE_C_CODE
        unsigned __int64 t = *x; 
        t = (t * b) + carry;
        *y = (K163_DIGIT)t;
        carry = (K163_DIGIT)(t >> 32);
#else
        __asm   mov ecx, x
        __asm   mov eax, [ecx]
        __asm   mul b
        __asm   mov ecx, y
        __asm   add eax, carry
        __asm   adc edx, 0
        __asm   mov [ecx],eax
        __asm   mov carry, edx
#endif
    }
    *y = carry;
}

// Computes z = x+y
int K163_Add( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y, int digits )
{
    K163_DIGIT carry;

    for( carry = 0; digits > 0; digits--, x++, y++, z++ )
    {
#ifdef USE_C_CODE
        K163_DIGIT t = (*x) + carry;
        carry = (t < (*x)) ? 1 : 0;
        *z = t + (*y);
        if( (*z) < t ) carry++;
#else
        __asm   mov ecx, x
        __asm   mov edx, y
        __asm   mov eax, [ecx]
        __asm   rcr carry, 1
        __asm   mov ecx, z
        __asm   adc eax, [edx]
        __asm   rcl carry, 1
        __asm   mov [ecx],eax
#endif
    }
    return carry;
}

// Computes z = x-y
int K163_Sub( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y, int digits )
{
    K163_DIGIT carry;

    for( carry = 0; digits > 0; digits--, x++, y++, z++ )
    {
#ifdef USE_C_CODE
        K163_DIGIT t = (*x) - carry;
        carry = (t > (*x)) ? 1 : 0;
        *z = t - (*y);
        if( (*z) > t ) carry++;
#else
        __asm   mov ecx, x
        __asm   mov edx, y
        __asm   mov eax, [ecx]
        __asm   rcr carry, 1
        __asm   mov ecx, z
        __asm   sbb eax, [edx]
        __asm   rcl carry, 1
        __asm   mov [ecx],eax
#endif
    }
    return carry;
}

// calculate z = x*y*(1/R) mod m
void K163_MontMul( K163_DIGIT * z, K163_DIGIT * x, K163_DIGIT * y )
{
    K163_DIGIT a[K163_DIGITS+2], u[K163_DIGITS+1];
    int i;

    K163_AssignZero( a , K163_DIGITS+1 );   // A=0

    for( i = 0; i < K163_DIGITS; i++ )
    {
        a[K163_DIGITS+1] = 0;
        K163_DigitMul( u, x[i], y, K163_DIGITS );
        K163_Add( a, a+1, u, K163_DIGITS+1 );       // A = A + xi*y

        K163_DigitMul( u, a[0] * K163_BPO_INV, K163_BPO, K163_DIGITS );
        if( K163_Sub( a, a, u, K163_DIGITS+1 ))
        {
            K163_Add( a+1, a+1, K163_BPO, K163_DIGITS );
        }
    }

    K163_Assign( z, a+1, K163_DIGITS );
}

void K163_BytesToDigits( 
    unsigned char * src,
    K163_DIGIT    * dst )
{
    dst[5] = src[0];
    dst[4] = GetMSBF32(src+1);
    dst[3] = GetMSBF32(src+5);
    dst[2] = GetMSBF32(src+9);
    dst[1] = GetMSBF32(src+13);
    dst[0] = GetMSBF32(src+17);
}

void K163_DigitsToBytes( 
    K163_DIGIT    * src,
    unsigned char * dst )
{
    dst[0] = (unsigned char)src[5];
    PutMSBF32(dst+1,src[4]);
    PutMSBF32(dst+5,src[3]);
    PutMSBF32(dst+9,src[2]);
    PutMSBF32(dst+13,src[1]);
    PutMSBF32(dst+17,src[0]);
}

// In:  x
// Out: y = R/x mod BPO

void K163_MontInv( 
    K163_DIGIT * y,     // out
    K163_DIGIT * x )    // in
{
    int i;
    K163_DIGIT k, z[K163_DIGITS];

    K163_MontMul( z, x, K163_BPO_R2 );    // z = x.R mod BPO

    K163_Assign( y, K163_BPO_R1, K163_DIGITS );

    for( i = K163_DIGITS; i > 0 && K163_BPO_M2[i-1] == 0; i-- );

    while( i-- )
    {
        for( k = 0x80000000; k != 0; k >>= 1 )
        {
            K163_MontMul( y, y, y );        // y = mont(y,y)
            if( K163_BPO_M2[i] & k )
            {
                K163_MontMul( y, y, z );    // w = mont(y,z)
            }
        }
    }
}

#define LSHIFT(co,x,ci) { co=((x)&0x80000000)?1:0; x=((x)<<1)^ci; }

unsigned int shift_left( PF2N a )
{
    unsigned int c1,c2;

    LSHIFT(c1,a->e[5],0);
    LSHIFT(c2,a->e[4],c1);
    LSHIFT(c1,a->e[3],c2);
    LSHIFT(c2,a->e[2],c1);
    LSHIFT(c1,a->e[1],c2);
    LSHIFT(c2,a->e[0],c1);
    return c2;
}

// c = a+b
void K163_PolyAdd( PF2N c, PF2N a, PF2N b )
{
    c->e[5] = a->e[5] ^ b->e[5];
    c->e[4] = a->e[4] ^ b->e[4];
    c->e[3] = a->e[3] ^ b->e[3];
    c->e[2] = a->e[2] ^ b->e[2];
    c->e[1] = a->e[1] ^ b->e[1];
    c->e[0] = a->e[0] ^ b->e[0];
}

/*  Polynomial multiplication modulo poly_prime.  */

void K163_PolyMul( PF2N c, PF2N a, PF2N b )
{
    unsigned int i;
    ELEMENT d;
    F2N t;
    
    K163_F2NZero( &t );

    for( i = 0, d = 0x04;; )
    {
        shift_left( &t );
        if( t.e[0] & 8 ) 
        {
            t.e[0] &= 7;
            t.e[5] ^= 0xC9;
        }

        if( d & b->e[i] ) K163_PolyAdd( &t, a, &t );
        d >>= 1;
        if( d == 0 )
        {
            if( i >= 5 ) break;
            d = 0x80000000;
            i++;
        }
    }

    t.e[0] &= 7;
    *c = t;
}

void mont_add( PF2N x1, PF2N z1, PF2N x2, PF2N z2, PF2N x0 )
{
    F2N u1, u2;

    K163_PolyMul( &u1, z2, x1 );
    K163_PolyMul( &u2, z1, x2 );
    K163_PolyMul( x1, &u2, &u1 );

    K163_PolyAdd( &u1, &u2, &u1 );
    K163_PolyMul( z1, &u1, &u1 );
    K163_PolyMul( &u2, z1, x0 );
    K163_PolyAdd( x1, &u2, x1 );
}

void mont_double( PF2N x1, PF2N z1 )
{
    F2N t1, t2;

    K163_PolyAdd( &t1, z1, x1 );
    K163_PolyMul( &t2, z1, x1 );
    K163_PolyMul( z1, &t2, &t2 );       // Z = (X.Z)^2
    K163_PolyMul( &t2, &t1, &t1 );
    K163_PolyMul( x1, &t2, &t2 );       // X = (X + bZ)^4
}

#define GET_MSBF32(x,i) ((x[i]<<24)|(x[i+1]<<16)|(x[i+2]<<8)|x[i+3])
#define PUT_MSBF32(b,i,x) \
    b[i+0] = (unsigned char)(x>>24); \
    b[i+1] = (unsigned char)(x>>16); \
    b[i+2] = (unsigned char)(x>> 8); \
    b[i+3] = (unsigned char)(x);

void K163_ByteArrayToField(
   unsigned char * pByteArray, 
   F2N           * pField )
{
    pField->e[0] = pByteArray[0];
    pField->e[1] = GET_MSBF32(pByteArray,1);
    pField->e[2] = GET_MSBF32(pByteArray,5);
    pField->e[3] = GET_MSBF32(pByteArray,9);
    pField->e[4] = GET_MSBF32(pByteArray,13);
    pField->e[5] = GET_MSBF32(pByteArray,17);
}

void K163_FieldToByteArray(
   F2N           * pField,
   unsigned char * pByteArray )
{
    pByteArray[0] = (unsigned char)pField->e[0];
    PUT_MSBF32( pByteArray, 1, pField->e[1] );
    PUT_MSBF32( pByteArray, 5, pField->e[2] );
    PUT_MSBF32( pByteArray, 9, pField->e[3] );
    PUT_MSBF32( pByteArray, 13, pField->e[4] );
    PUT_MSBF32( pByteArray, 17, pField->e[5] );
}

void point_multiply( PF2N_POINT Q, unsigned char * k, int size, PF2N_POINT P );

void K163_CalculatePublicKey(
    unsigned char * PrivateKey,                 // [in]
    unsigned long   Size,                       // [in]
    PK163_POINT     PublicKey )                 // [out]
{
    F2N_POINT Q;
    point_multiply( &Q, PrivateKey, Size, &base_point );
    K163_FieldToByteArray( &Q.x, PublicKey->X );
    K163_FieldToByteArray( &Q.y, PublicKey->Y );
}

void K163_CreateSharedKey(
    PK163_POINT     PublicKey,                  // [in]
    unsigned long   Flags,                      // [in]
    unsigned char * Multiplier,                 // [in]
    unsigned long   MultiplierSize,             // [in]
    unsigned char * SessionInfo,                // [out][21 bytes]
    unsigned char * SharedKey )                 // [out][16 bytes]
{
    F2N_POINT P, Q;
    unsigned char buff[21];

    // SessionInfo = k.Base     k=random multiplier
    point_multiply( &Q, Multiplier, MultiplierSize, &base_point );
    K163_FieldToByteArray( &Q.x, SessionInfo );

    // SharedKey   = x(k.PubKey)
    K163_ByteArrayToField( PublicKey->X, &P.x );
    K163_ByteArrayToField( PublicKey->Y, &P.y );
    point_multiply( &Q, Multiplier, MultiplierSize, &P );

    // Take the least significant 16 bytes as the session key
    K163_FieldToByteArray( &Q.x, buff );
    // Based on key type take different part of the x(k.PubKey)
    memcpy( SharedKey, buff+2+(Flags & 3), 16 );

    // Clear sensitive data
    memset( buff, 0, sizeof(buff) );
    K163_F2NZero( &Q.x );
    K163_F2NZero( &Q.y );
}

void K163_XOnlyMultiply( unsigned char *x, unsigned char *multiplier, int size, unsigned char *w )
{
    F2N_POINT Q, W;

    K163_ByteArrayToField( x, &Q.x );
    K163_F2NZero( &Q.y );

    point_multiply( &W, multiplier, size, &Q );
    K163_FieldToByteArray( &W.x, w );

    // Clear sensitive data
    K163_F2NZero( &W.x );
    K163_F2NZero( &W.y );
}

// Calculate Q = k.P
void point_multiply( PF2N_POINT Q, unsigned char * k, int size, PF2N_POINT P )
{
    int i;
    unsigned char d;
    F2N x1, z1, x2, z2, t1, t2;

    // Find 1st non-zero bit
    for( i = 0, d = 0x80;; )
    {
        if( d & k[i] ) break;
        d >>= 1;
        if( d == 0 )
        {
            d = 0x80;
            i++;
            if( i >= size )
            {
                K163_F2NZero( &Q->x );
                K163_F2NZero( &Q->y );
                return;
            }
        }
    }

    // Init first
    x1 = P->x;                          // X1 = x
    K163_F2NZero( &z1 );
    z1.e[5] = 1;                        // Z1 = 1
    K163_PolyMul( &z2, &x1, &x1 );      // Z2 = x^2
    K163_PolyMul( &x2, &z2, &z2 );
    x2.e[5] ^= 1;                       // X2 = x^4 + b

    for( ;; )
    {
        d >>= 1;
        if( d == 0 )
        {
            d = 0x80;
            i++;
            if( i >= size ) break;
        }

        if( d & k[i] )
        {
            mont_add( &x1, &z1, &x2, &z2, &P->x );
            mont_double( &x2, &z2 );
        }
        else
        {
            mont_add( &x2, &z2, &x1, &z1, &P->x );
            mont_double( &x1, &z1 );
        }
    }

    // Normalize X and compute Y

    K163_PolyMul( &x1, &z2, &x1 );   // X1.Z2
    K163_PolyMul( &x2, &z1, &x2 );   // X2.Z1
    K163_PolyMul( &t1, &z2, &z1 );   // Z1.Z2
    K163_PolyInv( &t2, &t1 );        // 1/(Z1.Z2)
    K163_PolyMul( &Q->x, &t2, &x1 ); // x1=X1/Z1
    K163_PolyMul( &x2, &t2, &x2 );   // x2=X2/Z2

    // Compute Q->y
    K163_PolyAdd( &x1, &P->x, &Q->x );
    K163_PolyAdd( &x2, &P->x, &x2 );
    K163_PolyMul( &t1, &x2, &x1 );      // (x1+x0)(x2+x0)
    K163_PolyMul( &t2, &P->x, &P->x );
    K163_PolyAdd( &t2, &P->y, &t2 );    // x0^2+y0
    K163_PolyAdd( &t1, &t2, &t1 );
    K163_PolyMul( &t2, &x1, &t1 );
    K163_PolyInv( &t1, &P->x );
    K163_PolyMul( &z1, &t2, &t1 );   // (x1+x0)(x2+x0)
    K163_PolyAdd( &Q->y, &P->y, &z1 );
}

// Calculate z = x - y
unsigned long f2n_sub( PF2N z, PF2N x, PF2N y )
{
    unsigned long c;

    z->e[5] = x->e[5] - y->e[5]    ; c = (z->e[5] > x->e[5]) ? 1 : 0;
    z->e[4] = x->e[4] - y->e[4] - c; c = (z->e[4] > x->e[4]) ? 1 : 0;
    z->e[3] = x->e[3] - y->e[3] - c; c = (z->e[3] > x->e[3]) ? 1 : 0;
    z->e[2] = x->e[2] - y->e[2] - c; c = (z->e[2] > x->e[2]) ? 1 : 0;
    z->e[1] = x->e[1] - y->e[1] - c; c = (z->e[1] > x->e[1]) ? 1 : 0;
    z->e[0] = x->e[0] - y->e[0] - c; c = (z->e[0] > x->e[0]) ? 1 : 0;

    return c;
}

// Calculate z = x + y
unsigned long f2n_add( PF2N z, PF2N x, PF2N y )
{
    unsigned long c;

    z->e[5] = x->e[5] + y->e[5]    ; c = (z->e[5] < x->e[5]) ? 1 : 0;
    z->e[4] = x->e[4] + y->e[4] + c; c = (z->e[4] < x->e[4]) ? 1 : 0;
    z->e[3] = x->e[3] + y->e[3] + c; c = (z->e[3] < x->e[3]) ? 1 : 0;
    z->e[2] = x->e[2] + y->e[2] + c; c = (z->e[2] < x->e[2]) ? 1 : 0;
    z->e[1] = x->e[1] + y->e[1] + c; c = (z->e[1] < x->e[1]) ? 1 : 0;
    z->e[0] = x->e[0] + y->e[0] + c; c = (z->e[0] < x->e[0]) ? 1 : 0;

    return c;
}

void K163_PointAdd( PF2N_POINT p3, PF2N_POINT p1, PF2N_POINT p2 )
{
    F2N x1, t1, t2, t3;
    
/*  compute theta = (y1 + y2)/(x1 + x2)  */
    K163_PolyAdd( &x1, &p2->x, &p1->x );    // x1 = x1+x2
    K163_PolyAdd( &t3, &p2->y, &p1->y );
    K163_PolyInv( &t2, &x1 );           // t2 = 1/(x1+x2)
    K163_PolyMul( &t1, &t2, &t3 );      // t1 = theta
    K163_PolyMul( &t2, &t1, &t1 );      // t2 = theta^2
    K163_PolyAdd( &x1, &x1, &t1 );
    K163_PolyAdd( &p3->x, &x1, &t2 );
    p3->x.e[5] ^= 1;

/*  next find y_3  */

    K163_PolyAdd( &x1, &p3->x, &p1->x );
    K163_PolyMul( &t3, &t1, &x1 );
    K163_PolyAdd( &p3->y, &p3->x, &t3 );
    K163_PolyAdd( &p3->y, &p3->y, &p1->y );
}

/*  K163_F2NZero out a F2N variable.  Make inline for speed.  */

void K163_F2NZero( PF2N a )
{
    a->e[0] = a->e[1] = a->e[2] = a->e[3] = a->e[4] = a->e[5] = 0;
}

int K163_IsF2NZero( PF2N a )
{
    return ((a->e[0] | a->e[1] | a->e[2] | a->e[3] | a->e[4] | a->e[5]) == 0) ? 1 : 0;
}

/*
; Calculate b = 1/z mod p(x)
; b = 1, c = 0, u = z, v = p
; while( deg(u) != 0 )
; {
;   j = deg(u) - deg(v)
;   if( j < 0 ) j -= j, xch(u,v), xch(b,c)
;   u ^= v<<j
;   b ^= c<<j
; }
*/
void K163_PolyInv( PF2N r, PF2N a )
{
    int i;
    ELEMENT m;
    F2N u, v, b, c, t1, t2;
    int k = 0;

    u = *a;
    v.e[0] = 8; v.e[1] = v.e[2] = v.e[3] = v.e[4] = 0; v.e[5] = 0xC9;
    K163_F2NZero( &b ); b.e[5] = 1;
    K163_F2NZero( &c );

    m = 0x08; i = 0;

    while( ((u.e[5] >> 1) | u.e[4] | u.e[3] | u.e[2] | u.e[1] | u.e[0]) != 0 )
    {
        if( u.e[i] & m )
        {
            if( v.e[i] & m )
            {
                // Both u & v are aligned, xor without shift
                K163_PolyAdd( &u, &v, &u );
                K163_PolyAdd( &b, &c, &b );
            }
            else
            {
                t1 = v;
                t2 = c;
                if( K163_IsF2NZero( &t1 ) || K163_IsF2NZero( &t2 ))
                {
                    break;
                }
                k = 0;
                while( (t1.e[i] & m) == 0 )
                {
                    shift_left( &t1 );
                    shift_left( &t2 );
                    k++;
                    if(k > 193 ) {  goto end;   }
                }
                K163_PolyAdd( &u, &t1, &u );
                K163_PolyAdd( &b, &t2, &b );
            }
        }
        else
        {
            if( v.e[i] & m )
            {
                // deg(u) < deg(v), swap the two
                t1 = u; u = v; v = t1;
                t2 = b; b = c; c = t2;
                if( K163_IsF2NZero( &t1 ) || K163_IsF2NZero( &t2 ))
                {
                    break;
                }
                k = 0; 
                while( (t1.e[i] & m) == 0 )
                {
                    shift_left( &t1 );
                    shift_left( &t2 );
                    k++;
                    if(k > 193 ) {  goto end;   }
                }
                K163_PolyAdd( &u, &t1, &u );
                K163_PolyAdd( &b, &t2, &b );
            }
            else
            {
                m >>= 1;
                if( m == 0 ) { i++; m = 0x80000000; }
            }
        }
    }
end:
    b.e[0] &= 7;
    *r = b;
}

#ifdef INCL_K163_SIGN
void K163_SSHSignature( 
    unsigned char  * d,         // [in] Private key, 21 bytes
    unsigned char  * m,         // [in] h(m), 20 bytes
    K163_SIGNATURE * Sig )      // [out] sig
{
    unsigned char k[21];
    F2N_POINT Q;
    K163_DIGIT w[K163_DIGITS], t[K163_DIGITS];

    GenRandom( k, sizeof(k) );
    k[0] &= 7;

    // r = x(k.P) + h(m)  (mod n)

    point_multiply( &Q, k, 21, &base_point );

    // m is 20 bytes (SHA1 digest)
    t[5] = 0;
    t[4] = GetMSBF32(m+0);
    t[3] = GetMSBF32(m+4);
    t[2] = GetMSBF32(m+8);
    t[1] = GetMSBF32(m+12);
    t[0] = GetMSBF32(m+16);

    w[0] = Q.x.e[5];
    w[1] = Q.x.e[4];
    w[2] = Q.x.e[3];
    w[3] = Q.x.e[2];
    w[4] = Q.x.e[1];
    w[5] = Q.x.e[0];

    K163_Add( t, w, t, K163_DIGITS );

    // calculate t mod BPO
    while( K163_Sub( t, t, K163_BPO, K163_DIGITS ) == 0 );
    K163_Add( t, t, K163_BPO, K163_DIGITS );

    K163_DigitsToBytes( t, Sig->R );

    // s = k - r.d  (mod n)

    K163_BytesToDigits( d, w );

    // simulation of x = t*w mod BPO
    {
        int i;
        K163_DIGIT j;
        K163_DIGIT x[K163_DIGITS], y[K163_DIGITS];

        x[0] = x[1] = x[2] = x[3] = x[4] = x[5] = 0;

        for( i = 5, j = 0x4; i >= 0; )
        {
            K163_Add( x, x, x, K163_DIGITS );
            if( !K163_Sub( y, x, K163_BPO, K163_DIGITS ))
                K163_Sub( x, x, K163_BPO, K163_DIGITS );

            if( w[i] & j )
            {
                K163_Add( x, x, t, K163_DIGITS );
                if( !K163_Sub( y, x, K163_BPO, K163_DIGITS ))
                    K163_Sub( x, x, K163_BPO, K163_DIGITS );
            }

            j >>= 1;
            if( j == 0 )
            {
                i--;
                j = 0x80000000;
            }
        }
    }
    K163_MontMul( t, t, w );    // t = r.d/R mod BPO
    K163_MontMul( w, t, K163_BPO_R2 );    // w = r.d/R.(R^2)/R = r.d mod BPO

    t[5] = k[0];
    t[4] = GetMSBF32(k+1);
    t[3] = GetMSBF32(k+5);
    t[2] = GetMSBF32(k+9);
    t[1] = GetMSBF32(k+13);
    t[0] = GetMSBF32(k+17);

    if( K163_Sub( t, t, w, K163_DIGITS ))
    {
        K163_Add( t, t, K163_BPO, K163_DIGITS );
    }

    K163_DigitsToBytes( t, Sig->S );
}

void K163_DSASignature( 
    unsigned char  * d,         // [in] Private key, 21 bytes
    unsigned char  * m,         // [in] h(m), 20 bytes
    K163_SIGNATURE * Sig )      // [out] sig
{
    unsigned char k[21];
    F2N_POINT Q;
    K163_DIGIT w[K163_DIGITS], t[K163_DIGITS], z[K163_DIGITS];

    GenRandom( k, sizeof(k) );
    k[0] &= 7;

    // r = x(k.P)  (mod n)
    // s = (h(m) + r.d)/k  (mod n)

    point_multiply( &Q, k, 21, &base_point );
    w[0] = Q.x.e[5];
    w[1] = Q.x.e[4];
    w[2] = Q.x.e[3];
    w[3] = Q.x.e[2];
    w[4] = Q.x.e[1];
    w[5] = Q.x.e[0];
    K163_DigitsToBytes( w, Sig->R );

    K163_BytesToDigits( d, t );
    K163_MontMul( w, w, K163_BPO_R2 );    // w = R.r mod BPO
    K163_MontMul( w, w, t );    // w = R.r.d/R = r.d mod BPO

    // m is 20 bytes (SHA1 digest)
    t[5] = 0;
    t[4] = GetMSBF32(m+0);
    t[3] = GetMSBF32(m+4);
    t[2] = GetMSBF32(m+8);
    t[1] = GetMSBF32(m+12);
    t[0] = GetMSBF32(m+16);

    K163_Add( t, w, t, K163_DIGITS );   // t = h(m) + r.d

    // calculate t mod BPO
    while( K163_Sub( t, t, K163_BPO, K163_DIGITS ) == 0 );
    K163_Add( t, t, K163_BPO, K163_DIGITS );

    K163_BytesToDigits( k, w );
    K163_MontInv( z, w );       // z = R/k mod BPO
    K163_MontMul( w, w, t );    // w = (h(m) + r.d)/k  mod BPO

    K163_DigitsToBytes( w, Sig->S );
}

int K163_ECDSAVerify(
    unsigned char    * MsgDigest, 
    PK163_POINT        PubKey,
    PK163_SIGNATURE    Sig )
{
    unsigned char u1[21], u2[21];
    F2N_POINT P1, P2, P3;
    K163_DIGIT w[K163_DIGITS], z[K163_DIGITS], t[K163_DIGITS];

    // w = 1/s               (mod BPO)
    // u1 = msg*w, u2 = r*w  (mod BPO)
    // v = X(u1.P + u2.Q)    (mod BPO)
    // return (v == r)? 1 : 0

    // Calculate w = R/s mod BPO
    K163_BytesToDigits( Sig->S, t );
    K163_MontInv( w, t );

    // m is 20 bytes (SHA1 digest)
    t[5] = 0;
    t[4] = GetMSBF32(MsgDigest+0);
    t[3] = GetMSBF32(MsgDigest+4);
    t[2] = GetMSBF32(MsgDigest+8);
    t[1] = GetMSBF32(MsgDigest+12);
    t[0] = GetMSBF32(MsgDigest+16);

    K163_MontMul( z, t, w );    // u1 = m.(R/s)/R = m/s mod BPO
    K163_DigitsToBytes( z, u1 );

    K163_BytesToDigits( Sig->R, t ); // u2 = r.(R/s)/R = r/s mod BPO
    K163_MontMul( z, t, w );    
    K163_DigitsToBytes( z, u2 );

    K163_ByteArrayToField( PubKey->X, &P3.x );
    K163_ByteArrayToField( PubKey->Y, &P3.y );

    point_multiply( &P1, u1, 21, &base_point );
    point_multiply( &P2, u2, 21, &P3 );

    // Calculate P3 = P1+P2
    K163_PointAdd( &P3, &P1, &P2 );

    // Calculate P3.x mod BPO
    if( f2n_sub( &P1.x, &P3.x, &base_point_order ))
        K163_FieldToByteArray( &P3.x, u1 );
    else
        K163_FieldToByteArray( &P1.x, u1 );

    return (memcmp( u1, Sig->R, sizeof(Sig->R) ) == 0)? 1 : 0;
}

int K163_ECSSHVerify(
    unsigned char    * MsgDigest, 
    PK163_POINT        PubKey,
    PK163_SIGNATURE    Sig )
{
    F2N u;
    unsigned char t[21];
    F2N_POINT P1, P2, P3;

    // v = X(s.P + r.Q) + h(m)    (mod BPO)
    // return (v == r)? 1 : 0

    K163_ByteArrayToField( PubKey->X, &P3.x );
    K163_ByteArrayToField( PubKey->Y, &P3.y );

    point_multiply( &P1, Sig->S, 21, &base_point );
    point_multiply( &P2, Sig->R, 21, &P3 );

    // Calculate P3 = P1+P2
    K163_PointAdd( &P3, &P1, &P2 );

    // m is 20 bytes (SHA1 digest)
    u.e[0] = 0;
    u.e[1] = GetMSBF32(MsgDigest+0);
    u.e[2] = GetMSBF32(MsgDigest+4);
    u.e[3] = GetMSBF32(MsgDigest+8);
    u.e[4] = GetMSBF32(MsgDigest+12);
    u.e[5] = GetMSBF32(MsgDigest+16);

    f2n_add( &u, &P3.x, &u );

    // Calculate u mod BPO
    if( f2n_sub( &P1.x, &u, &base_point_order ))
        K163_FieldToByteArray( &u, t );
    else
    {
        if( f2n_sub( &P1.y, &P1.x, &base_point_order ))
            K163_FieldToByteArray( &P1.x, t );
        else
        {
            if( f2n_sub( &P1.x, &P1.y, &base_point_order ))
                K163_FieldToByteArray( &P1.y, t );
            else
                K163_FieldToByteArray( &P1.x, t );
        }
    }

    return (memcmp( t, Sig->R, sizeof(Sig->R) ) == 0) ? 1 : 0;
}
#endif
