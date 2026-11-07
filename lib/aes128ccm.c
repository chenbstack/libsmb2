/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2019 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

#include "portable-endian.h"
#include "aes.h"

static void aes_ccm_generate_b0(unsigned char *nonce, size_t nlen,
                                size_t alen, size_t plen, size_t mlen,
                                unsigned char *buf)
{
        uint32_t len;

        memset(buf, 0, 16);
        if (alen) {
                buf[0] |= 0x40;                   /* Adata */
        }
        buf[0] |= (((mlen - 2) / 2) << 3) & 0x38; /* M' */
        buf[0] |= (15 - nlen - 1) & 0x07;         /* L' */

        len = htobe32((uint32_t)plen);
        memcpy(&buf[12], &len, 4);
        memcpy(&buf[1], nonce, nlen);
}

static inline void bxory(unsigned char *b, unsigned char *y, size_t num)
{
        int i;

        for(i = 0; i < (int)num; i++) {
                b[i] = b[i] ^ y[i];
        }
}

#ifndef __APPLE__
static void ccm_generate_T(unsigned char *key,
                           unsigned char *nonce, size_t nlen,
                           unsigned char *aad, size_t alen,
                           unsigned char *p, size_t plen,
                           unsigned char *m, size_t mlen)
{
        unsigned char b[16] _U_, y[16]_U_;
        uint16_t l;

        aes_ccm_generate_b0(nonce, nlen, alen, plen, mlen, &b[0]);
        AES128_ECB_encrypt(b, key, y);

        /* Create Aad */
        if (alen) {
                /* First block */
                memset(b, 0, 16);
                l = htobe16((uint16_t)alen);
                memcpy(b, &l, 2);

                l = (alen > 14) ? 14 : (uint16_t)alen;
                memcpy(&b[2], aad, l);
                aad  += l;
                alen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);

                while (alen) {
                        memset(b, 0, 16);
                        l = (alen > 16) ? 16 : (uint16_t)alen;
                        memcpy(b, aad, l);
                        aad  += l;
                        alen -= l;

                        bxory(b, y, 16);
                        AES128_ECB_encrypt(b, key, y);
                }
        }

        /* Create Payload */
        while (plen) {
                memset(b, 0, 16);
                l = (plen > 16) ? 16 : (uint16_t)plen;
                memcpy(b, p, l);
                p    += l;
                plen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);
        }

        memcpy(m, y, mlen);
}

static void ccm_generate_s(unsigned char *key, unsigned char *nonce, size_t nlen,
                           size_t plen, int i, unsigned char *s)
{
        uint32_t l;

        memset(s, 0, 16);
        s[0] |= (15 - nlen - 1) & 0x07;

        l = htobe32(i);
        memcpy(&s[12], &l, 4);

        memcpy(&s[1], nonce, nlen);

        AES128_ECB_encrypt(s, key, s);
}

static void aes_ccm_crypt(unsigned char *key,
                          unsigned char *nonce, size_t nlen,
                          unsigned char *p, size_t plen)
{
        int j;
        size_t l;
        unsigned char s[16] _U_;

        j = 0;
        while (plen) {
                l = (plen > 16) ? 16 : plen;
                ccm_generate_s(key, nonce, nlen, plen, j + 1, &s[0]);
                bxory(&p[j * 16], &s[0], l);

                j++;
                plen -= l;
        }
}

static void aes128ccm_encrypt_reference(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        ccm_generate_s(key, nonce, nlen, plen, 0, &s[0]);
        bxory(m, &s[0], mlen);

        aes_ccm_crypt(key, nonce, nlen, p, plen);
}

static int aes128ccm_decrypt_reference(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;
        unsigned char tmp[16];

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, tmp, mlen);
        ccm_generate_s(key, nonce, nlen, plen, 0, &s[0]);
        bxory(tmp, &s[0], mlen);

        return memcmp(tmp, m, mlen);
}
#endif /* !__APPLE__ */

#ifdef __APPLE__
#include <CommonCrypto/CommonCrypto.h>

/*
 * velum: Apple 平台：CBC-MAC 和 CTR 都整段交给 CommonCrypto（硬件 AES），
 * 不再每 16 字节创建一次 cryptor。密钥 16 或 32 字节（AES-128 / AES-256）。
 */
#define CCM_CHUNK 4096

/* velum: 把 len（16 的倍数）字节喂进 CBC cryptor，last 保存最后一块密文。 */
static int ccm_cbc_feed(CCCryptorRef c, const unsigned char *in, size_t len,
                        unsigned char last[16])
{
        unsigned char out[CCM_CHUNK];
        size_t moved;

        while (len) {
                size_t n = len > CCM_CHUNK ? CCM_CHUNK : len;
                if (CCCryptorUpdate(c, in, n, out, sizeof(out), &moved) != kCCSuccess ||
                    moved != n) {
                        return -1;
                }
                memcpy(last, &out[n - 16], 16);
                in  += n;
                len -= n;
        }
        return 0;
}

/* velum: 喂入 len 字节，不足 16 的尾部补零。 */
static int ccm_cbc_feed_padded(CCCryptorRef c, const unsigned char *in, size_t len,
                               unsigned char last[16])
{
        size_t full = len & ~(size_t)15;
        unsigned char b[16];

        if (full && ccm_cbc_feed(c, in, full, last)) {
                return -1;
        }
        if (len > full) {
                memset(b, 0, 16);
                memcpy(b, in + full, len - full);
                if (ccm_cbc_feed(c, b, 16, last)) {
                        return -1;
                }
        }
        return 0;
}

static int ccm_tag(const unsigned char *key, size_t klen,
                   unsigned char *nonce, size_t nlen,
                   const unsigned char *aad, size_t alen,
                   const unsigned char *p, size_t plen,
                   size_t mlen, unsigned char t[16])
{
        static const unsigned char zero_iv[16] = {0};
        unsigned char b[16], stack_aad[256];
        unsigned char *fa = stack_aad;
        CCCryptorRef c = NULL;
        int rc = -1;

        if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCBC, kCCAlgorithmAES,
                                    ccNoPadding, zero_iv, key, klen, NULL, 0,
                                    0, 0, &c) != kCCSuccess) {
                return -1;
        }
        aes_ccm_generate_b0(nonce, nlen, alen, plen, mlen, b);
        if (ccm_cbc_feed(c, b, 16, t)) {
                goto out;
        }
        if (alen) {
                /* velum: 2 字节长度 + AAD，补零到 16 的倍数（SMB 的 AAD 固定 32 字节） */
                size_t flen = 2 + alen;
                if (flen > sizeof(stack_aad) && (fa = malloc(flen)) == NULL) {
                        fa = stack_aad;
                        goto out;
                }
                fa[0] = (unsigned char)(alen >> 8);
                fa[1] = (unsigned char)alen;
                memcpy(fa + 2, aad, alen);
                if (ccm_cbc_feed_padded(c, fa, flen, t)) {
                        goto out;
                }
        }
        if (ccm_cbc_feed_padded(c, p, plen, t)) {
                goto out;
        }
        rc = 0;
out:
        if (fa != stack_aad) {
                free(fa);
        }
        CCCryptorRelease(c);
        return rc;
}

/*
 * velum: CTR：计数块 A_i = 标志 | nonce | 计数。cryptor 从 A_0 开始，
 * 先加密 16 字节零得到 S_0（用于标签），随后计数为 1、2…正好对应负载。
 */
static int ccm_ctr(const unsigned char *key, size_t klen,
                   unsigned char *nonce, size_t nlen,
                   unsigned char *p, size_t plen, unsigned char s0[16])
{
        unsigned char a0[16], zero[16] = {0};
        unsigned char buf[CCM_CHUNK];
        CCCryptorRef c = NULL;
        size_t moved;
        int rc = -1;

        memset(a0, 0, 16);
        a0[0] = (15 - nlen - 1) & 0x07;
        memcpy(&a0[1], nonce, nlen);
        if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES,
                                    ccNoPadding, a0, key, klen, NULL, 0, 0,
                                    kCCModeOptionCTR_BE, &c) != kCCSuccess) {
                return -1;
        }
        if (CCCryptorUpdate(c, zero, 16, s0, 16, &moved) != kCCSuccess || moved != 16) {
                goto out;
        }
        while (plen) {
                size_t n = plen > CCM_CHUNK ? CCM_CHUNK : plen;
                if (CCCryptorUpdate(c, p, n, buf, sizeof(buf), &moved) != kCCSuccess ||
                    moved != n) {
                        goto out;
                }
                memcpy(p, buf, n);
                p    += n;
                plen -= n;
        }
        rc = 0;
out:
        CCCryptorRelease(c);
        return rc;
}

int smb3_aes_ccm_encrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen)
{
        unsigned char t[16], s0[16];

        if (ccm_tag(key, klen, nonce, nlen, aad, alen, p, plen, mlen, t) ||
            ccm_ctr(key, klen, nonce, nlen, p, plen, s0)) {
                return -1;
        }
        bxory(t, s0, mlen);
        memcpy(m, t, mlen);
        return 0;
}

int smb3_aes_ccm_decrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen)
{
        unsigned char t[16], s0[16], diff = 0;
        size_t i;

        if (ccm_ctr(key, klen, nonce, nlen, p, plen, s0) ||
            ccm_tag(key, klen, nonce, nlen, aad, alen, p, plen, mlen, t)) {
                return -1;
        }
        bxory(t, s0, mlen);
        for (i = 0; i < mlen; i++) {
                diff |= t[i] ^ m[i];
        }
        return diff ? -1 : 0;
}

#else /* !__APPLE__ */

int smb3_aes_ccm_encrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen)
{
        if (klen != 16) {
                return -1; /* 参考实现只有 AES-128 */
        }
        aes128ccm_encrypt_reference((unsigned char *)key, nonce, nlen, aad, alen, p, plen, m, mlen);
        return 0;
}

int smb3_aes_ccm_decrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen)
{
        if (klen != 16) {
                return -1;
        }
        return aes128ccm_decrypt_reference((unsigned char *)key, nonce, nlen, aad, alen, p, plen, m, mlen) ? -1 : 0;
}

#endif /* __APPLE__ */

void aes128ccm_encrypt(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen)
{
        smb3_aes_ccm_encrypt(key, 16, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        return smb3_aes_ccm_decrypt(key, 16, nonce, nlen, aad, alen, p, plen, m, mlen);
}
