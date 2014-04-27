/**
 * K-163 Koblitz curve    Written by: Mehdi Sotoodeh
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

// --------------------------------------------------------------------------
// Software only ECC support for K163
//
// Curve:   y^2 + xy = x^3 + x^2 + 1
//
// --------------------------------------------------------------------------

#ifndef __k163ecc_h_
#define __k163ecc_h_

#define K163_FIELD_BITS         163
#define K163_FIELD_BYTES        ((K163_FIELD_BITS+7)/8)

typedef struct 
{
    unsigned char X[K163_FIELD_BYTES];
    unsigned char Y[K163_FIELD_BYTES];
} K163_POINT, * PK163_POINT;

typedef struct 
{
    unsigned char X[K163_FIELD_BYTES];
    unsigned char Y[K163_FIELD_BYTES];
    unsigned char Order[K163_FIELD_BYTES];
} K163_BASE, * PK163_BASE;

typedef struct 
{
    unsigned char R[K163_FIELD_BYTES];
    unsigned char S[K163_FIELD_BYTES];
} K163_SIGNATURE, * PK163_SIGNATURE;

extern K163_POINT K163_BasePoint;
extern unsigned char K163_BasePointOrder[K163_FIELD_BYTES];

void K163_CreateSharedKey(
    PK163_POINT     PublicKey,              // [in]
    unsigned long   Flags,                  // [in]
    unsigned char * Multiplier,             // [in]
    unsigned long   MultiplierSize,         // [in]
    unsigned char * SessionInfo,            // [out][21 bytes]
    unsigned char * SharedKey );            // [out][16 bytes]

void K163_CalculatePublicKey(
    unsigned char * PrivateKey,             // [in]
    unsigned long   Size,                   // [in]
    PK163_POINT     PublicKey );            // [out]

void K163_XOnlyMultiply( 
    unsigned char * x,                      // [in]
    unsigned char * multiplier,             // [in]
    int size,                               // [in]
    unsigned char * w );                    // [out]

#endif // __k163ecc_h_