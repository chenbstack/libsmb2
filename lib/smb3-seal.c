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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS__IOVEC_H
#include <sys/_iovec.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <stdio.h>

#include "compat.h"

#include "portable-endian.h"

#include "aes128ccm.h"
#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "smb3-seal.h"

static const char xfer[4] = {0xFD, 'S', 'M', 'B'};

static smb2_gcm_fn gcm_encrypt;
static smb2_gcm_fn gcm_decrypt;

void smb2_set_gcm_impl(smb2_gcm_fn encrypt, smb2_gcm_fn decrypt)
{
        gcm_encrypt = encrypt;
        gcm_decrypt = decrypt;
}

static int cipher_is_gcm(uint16_t cipher)
{
        return cipher == SMB2_ENCRYPTION_AES_128_GCM ||
               cipher == SMB2_ENCRYPTION_AES_256_GCM;
}

int smb3_cipher_key_len(uint16_t cipher)
{
        switch (cipher) {
        case SMB2_ENCRYPTION_AES_128_CCM:
                return 16;
        case SMB2_ENCRYPTION_AES_128_GCM:
                return gcm_encrypt && gcm_decrypt ? 16 : 0;
#ifdef __APPLE__
        /* velum: AES-256-CCM 依赖 CommonCrypto 版的 CCM，参考实现只有 AES-128 */
        case SMB2_ENCRYPTION_AES_256_CCM:
                return 32;
#endif
        case SMB2_ENCRYPTION_AES_256_GCM:
                return gcm_encrypt && gcm_decrypt ? 32 : 0;
        default:
                return 0;
        }
}

int smb3_client_ciphers(uint16_t ciphers[4])
{
        /* velum: GCM 优先（硬件加速、只需一遍）；CCM 兜底，SMB 3.0 / 3.0.2 也只有 CCM */
        static const uint16_t preferred[4] = {
                SMB2_ENCRYPTION_AES_128_GCM, SMB2_ENCRYPTION_AES_128_CCM,
                SMB2_ENCRYPTION_AES_256_GCM, SMB2_ENCRYPTION_AES_256_CCM,
        };
        int i, n = 0;

        for (i = 0; i < 4; i++) {
                if (smb3_cipher_key_len(preferred[i])) {
                        ciphers[n++] = preferred[i];
                }
        }
        return n;
}

/* velum: SMB 3.0 / 3.0.2 没有协商上下文，算法固定为 AES-128-CCM */
static uint16_t effective_cipher(struct smb2_context *smb2)
{
        return smb2->cypher ? smb2->cypher : SMB2_ENCRYPTION_AES_128_CCM;
}

static void fill_nonce(uint8_t *buf, size_t len)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        arc4random_buf(buf, len);
#else
        size_t i;
        for (i = 0; i < len; i++) {
                buf[i] = random() & 0xff;
        }
#endif
}

int
smb3_encrypt_pdu(struct smb2_context *smb2,
                 struct smb2_pdu *pdu)
{
        struct smb2_pdu *tmp_pdu;
        uint32_t spl, u32;
        int i, rc, klen;
        uint16_t u16, cipher;

        if (!smb2->seal) {
                return 0;
        }
        if (!pdu->seal) {
                return 0;
        }
        cipher = effective_cipher(smb2);
        klen = smb3_cipher_key_len(cipher);
        if (klen == 0) {
                smb2_set_error(smb2, "Unsupported SMB3 encryption algorithm 0x%04x", cipher);
                pdu->seal = 0;
                return -1;
        }

        spl = 52;  /* transform header */
        for (tmp_pdu = pdu; tmp_pdu; tmp_pdu = tmp_pdu->next_compound) {
                for (i = 0; i < tmp_pdu->out.niov; i++) {
                        spl += (uint32_t)tmp_pdu->out.iov[i].len;
                }
        }
        pdu->crypt = calloc(spl, sizeof(uint8_t));
        if (pdu->crypt == NULL) {
                pdu->seal = 0;
                return -1;
        }

        memcpy(&pdu->crypt[0], xfer, 4);
        /* velum: Nonce 字段 16 字节：CCM 用前 11 字节、GCM 用前 12 字节，其余为 0 */
        fill_nonce(&pdu->crypt[20], cipher_is_gcm(cipher) ? 12 : 11);
        u32 = htole32(spl - 52);
        memcpy(&pdu->crypt[36], &u32, 4);
        /* velum: 3.0 / 3.0.2 为 EncryptionAlgorithm（CCM=1），3.1.1 为 Flags（Encrypted=1），值相同 */
        u16 = htole16(SMB_ENCRYPTION_AES128_CCM);
        memcpy(&pdu->crypt[42], &u16, 2);
        memcpy(&pdu->crypt[44], &smb2->session_id, 8);

        spl = 52;  /* transform header */
        for (tmp_pdu = pdu; tmp_pdu; tmp_pdu = tmp_pdu->next_compound) {
                for (i = 0; i < tmp_pdu->out.niov; i++) {
                        memcpy(&pdu->crypt[spl], tmp_pdu->out.iov[i].buf,
                               tmp_pdu->out.iov[i].len);
                        spl += (uint32_t)tmp_pdu->out.iov[i].len;
                }
        }

        if (cipher_is_gcm(cipher)) {
                rc = gcm_encrypt(smb2->serverin_key, klen,
                                 &pdu->crypt[20],
                                 &pdu->crypt[20], 32,
                                 &pdu->crypt[52], spl - 52,
                                 &pdu->crypt[4]);
        } else {
                rc = smb3_aes_ccm_encrypt(smb2->serverin_key, klen,
                                          &pdu->crypt[20], 11,
                                          &pdu->crypt[20], 32,
                                          &pdu->crypt[52], spl - 52,
                                          &pdu->crypt[4], 16);
        }
        if (rc) {
                smb2_set_error(smb2, "Failed to encrypt PDU");
                free(pdu->crypt);
                pdu->crypt = NULL;
                pdu->seal = 0;
                return -1;
        }
        pdu->crypt_len = spl;

        return 0;
}

int
smb3_decrypt_pdu(struct smb2_context *smb2)
{
        int rc, klen;
        uint16_t cipher = effective_cipher(smb2);
        uint8_t *hdr = smb2->in.iov[smb2->in.niov - 2].buf;
        uint8_t *data = smb2->in.iov[smb2->in.niov - 1].buf;
        size_t len = smb2->in.iov[smb2->in.niov - 1].len;

        klen = smb3_cipher_key_len(cipher);
        if (klen == 0) {
                smb2_set_error(smb2, "Unsupported SMB3 encryption algorithm 0x%04x", cipher);
                return -1;
        }
        if (cipher_is_gcm(cipher)) {
                rc = gcm_decrypt(smb2->serverout_key, klen,
                                 &hdr[20], &hdr[20], 32,
                                 data, len, &hdr[4]);
        } else {
                rc = smb3_aes_ccm_decrypt(smb2->serverout_key, klen,
                                          &hdr[20], 11, &hdr[20], 32,
                                          data, len, &hdr[4], 16);
        }
        if (rc) {
                smb2_set_error(smb2, "Failed to decrypt PDU");
                return -1;
        }

        if (smb2->in.num_done == 0) {
                smb2->enc = smb2->in.iov[smb2->in.niov - 1].buf;
                smb2->enc_len = smb2->in.iov[smb2->in.niov - 1].len;
                smb2->enc_pos = 0;
                smb2->in.iov[smb2->in.niov - 1].free = NULL;
                smb2_free_iovector(smb2, &smb2->in);

                smb2->spl = (uint32_t)smb2->enc_len;
                smb2->recv_state = SMB2_RECV_HEADER;
                smb2_add_iovector(smb2, &smb2->in, &smb2->header[0],
                                  SMB2_HEADER_SIZE, NULL);
        }

        rc = smb2_read_from_buf(smb2);
        free(smb2->enc);
        smb2->enc = NULL;

        return rc;
}
