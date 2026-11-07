/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _SMB3_SEAL_H_
#define _SMB3_SEAL_H_

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

#ifdef __cplusplus
extern "C" {
#endif

int
smb3_encrypt_pdu(struct smb2_context *smb2,
                 struct smb2_pdu *pdu);
int
smb3_decrypt_pdu(struct smb2_context *smb2);

/* velum: 本端能用的加密算法：返回密钥长度（16/32），不支持返回 0。 */
int smb3_cipher_key_len(uint16_t cipher);

/* velum: 客户端按偏好顺序通告的算法；返回个数（最多 4）。 */
int smb3_client_ciphers(uint16_t ciphers[4]);

#ifdef __cplusplus
}
#endif

#endif /* _SMB3_SEAL_H_ */
