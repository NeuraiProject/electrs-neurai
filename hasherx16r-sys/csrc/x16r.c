/*
 * X16R / X16Rv2 block header hashing, ported from Neurai v1.0.7 `src/hash.h`
 * (`HashX16R`, `HashX16RV2`, `GetHashSelection`) onto the bundled sphlib.
 *
 * `prev` is the previous block hash in internal (little-endian) byte order,
 * i.e. bytes 4..36 of the serialized header; `out` receives the first 32
 * bytes of the final 512-bit hash (`uint512::trim256()`), also in internal
 * byte order.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "sph_luffa.h"
#include "sph_cubehash.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_echo.h"
#include "sph_hamsi.h"
#include "sph_fugue.h"
#include "sph_shabal.h"
#include "sph_whirlpool.h"
#include "sph_sha2.h"
#include "sph_tiger.h"

/* uint256::GetNibble(48 + index) of the previous block hash */
static int hash_selection(const unsigned char prev[32], int index)
{
    int n = 63 - (48 + index);
    if (n % 2 == 1)
        return prev[n / 2] >> 4;
    return prev[n / 2] & 0x0F;
}

/* sph_tiger_close() writes 24 bytes into the (zeroed) 64-byte buffer; the
 * next function then hashes all 64 bytes, exactly like the C++ code. */
static void tiger_then(const void *in, size_t len, unsigned char out[64])
{
    sph_tiger_context ctx;
    memset(out, 0, 64);
    sph_tiger_init(&ctx);
    sph_tiger(&ctx, in, len);
    sph_tiger_close(&ctx, out);
}

static void x16r_impl(const unsigned char *input, size_t input_len,
                      const unsigned char prev[32], unsigned char out[32], int v2)
{
    unsigned char hash[16][64];
    memset(hash, 0, sizeof(hash));
    for (int i = 0; i < 16; i++) {
        const void *to_hash = (i == 0) ? (const void *)input : (const void *)hash[i - 1];
        size_t len = (i == 0) ? input_len : 64;
        unsigned char *dst = hash[i];
        switch (hash_selection(prev, i)) {
        case 0: { sph_blake512_context c; sph_blake512_init(&c); sph_blake512(&c, to_hash, len); sph_blake512_close(&c, dst); break; }
        case 1: { sph_bmw512_context c; sph_bmw512_init(&c); sph_bmw512(&c, to_hash, len); sph_bmw512_close(&c, dst); break; }
        case 2: { sph_groestl512_context c; sph_groestl512_init(&c); sph_groestl512(&c, to_hash, len); sph_groestl512_close(&c, dst); break; }
        case 3: { sph_jh512_context c; sph_jh512_init(&c); sph_jh512(&c, to_hash, len); sph_jh512_close(&c, dst); break; }
        case 4: {
            sph_keccak512_context c;
            if (v2) { tiger_then(to_hash, len, dst); to_hash = dst; len = 64; }
            sph_keccak512_init(&c); sph_keccak512(&c, to_hash, len); sph_keccak512_close(&c, dst); break;
        }
        case 5: { sph_skein512_context c; sph_skein512_init(&c); sph_skein512(&c, to_hash, len); sph_skein512_close(&c, dst); break; }
        case 6: {
            sph_luffa512_context c;
            if (v2) { tiger_then(to_hash, len, dst); to_hash = dst; len = 64; }
            sph_luffa512_init(&c); sph_luffa512(&c, to_hash, len); sph_luffa512_close(&c, dst); break;
        }
        case 7: { sph_cubehash512_context c; sph_cubehash512_init(&c); sph_cubehash512(&c, to_hash, len); sph_cubehash512_close(&c, dst); break; }
        case 8: { sph_shavite512_context c; sph_shavite512_init(&c); sph_shavite512(&c, to_hash, len); sph_shavite512_close(&c, dst); break; }
        case 9: { sph_simd512_context c; sph_simd512_init(&c); sph_simd512(&c, to_hash, len); sph_simd512_close(&c, dst); break; }
        case 10: { sph_echo512_context c; sph_echo512_init(&c); sph_echo512(&c, to_hash, len); sph_echo512_close(&c, dst); break; }
        case 11: { sph_hamsi512_context c; sph_hamsi512_init(&c); sph_hamsi512(&c, to_hash, len); sph_hamsi512_close(&c, dst); break; }
        case 12: { sph_fugue512_context c; sph_fugue512_init(&c); sph_fugue512(&c, to_hash, len); sph_fugue512_close(&c, dst); break; }
        case 13: { sph_shabal512_context c; sph_shabal512_init(&c); sph_shabal512(&c, to_hash, len); sph_shabal512_close(&c, dst); break; }
        case 14: { sph_whirlpool_context c; sph_whirlpool_init(&c); sph_whirlpool(&c, to_hash, len); sph_whirlpool_close(&c, dst); break; }
        case 15: {
            sph_sha512_context c;
            if (v2) { tiger_then(to_hash, len, dst); to_hash = dst; len = 64; }
            sph_sha512_init(&c); sph_sha512(&c, to_hash, len); sph_sha512_close(&c, dst); break;
        }
        }
    }
    memcpy(out, hash[15], 32);
}

void neurai_x16r(const unsigned char *input, size_t len, const unsigned char prev[32], unsigned char out[32])
{
    x16r_impl(input, len, prev, out, 0);
}

void neurai_x16rv2(const unsigned char *input, size_t len, const unsigned char prev[32], unsigned char out[32])
{
    x16r_impl(input, len, prev, out, 1);
}
