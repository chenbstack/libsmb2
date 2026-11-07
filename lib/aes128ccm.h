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
void aes128ccm_encrypt(unsigned char *key,
		       unsigned char *nonce, size_t nlen,
		       unsigned char *aad, size_t alen,
		       unsigned char *p, size_t plen,
		       unsigned char *m, size_t mlen);

/* velum: 通用 CCM：klen 为 16 或 32；返回 0 成功，解密时标签不符返回 -1。 */
int smb3_aes_ccm_encrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen);
int smb3_aes_ccm_decrypt(const unsigned char *key, size_t klen,
                         unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen,
                         unsigned char *p, size_t plen,
                         unsigned char *m, size_t mlen);
int aes128ccm_decrypt(unsigned char *key,
		      unsigned char *nonce, size_t nlen,
		      unsigned char *aad, size_t alen,
		      unsigned char *p, size_t plen,
		      unsigned char *m, size_t mlen);
