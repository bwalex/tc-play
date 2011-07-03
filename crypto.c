/*
 * Copyright (c) 2011 Alex Hornung <alex@alexhornung.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <errno.h>
#include <string.h>
#include <openssl/evp.h>

#include "crc32.h"
#include "tcplay.h"

int
tc_crypto_init(void)
{
	OpenSSL_add_all_algorithms();

	return 0;
}

int
tc_encrypt(struct tc_crypto_algo *cipher, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	const EVP_CIPHER *evp;
	EVP_CIPHER_CTX ctx;
	int outl, tmplen;

	evp = EVP_get_cipherbyname(cipher->name);
	if (evp == NULL) {
		fprintf(stderr, "Cipher %s not found\n", cipher->name);
		return ENOENT;
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx, evp, key, iv);
	EVP_EncryptUpdate(&ctx, out, &outl, in, in_len);
	EVP_EncryptFinal(&ctx, out + outl, &tmplen);

	return 0;
}

int
tc_decrypt(struct tc_crypto_algo *cipher, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	const EVP_CIPHER *evp;
	EVP_CIPHER_CTX ctx;
	int outl, tmplen;

	evp = EVP_get_cipherbyname(cipher->name);
	if (evp == NULL) {
		fprintf(stderr, "Cipher %s not found\n", cipher->name);
		return ENOENT;
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, evp, key, iv);
	EVP_DecryptUpdate(&ctx, out, &outl, in, in_len);
	EVP_DecryptFinal(&ctx, out + outl, &tmplen);

	return 0;
}

int
pbkdf2(const char *pass, int passlen, const unsigned char *salt, int saltlen,
    int iter, const char *hash_name, int keylen, unsigned char *out)
{
	const EVP_MD *md;
	int r;

	md = EVP_get_digestbyname(hash_name);
	if (md == NULL) {
		fprintf(stderr, "Hash %s not found\n", hash_name);
		return ENOENT;
	}
	r = PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, md,
	    keylen, out);

	if (r == 0) {
		printf("Error in PBKDF2\n");
		return EINVAL;
	}

	return 0;
}

int
apply_keyfiles(unsigned char *pass, size_t pass_memsz, const char *keyfiles[],
    int nkeyfiles)
{
	int pl, k;
	unsigned char *kpool;
	unsigned char *kdata;
	int kpool_idx;
	size_t i, kdata_sz;
	uint32_t crc;

	if (pass_memsz < MAX_PASSSZ) {
		fprintf(stderr, "Not enough memory for password manipluation\n");
		return ENOMEM;
	}

	pl = strlen(pass);
	memset(pass+pl, 0, MAX_PASSSZ-pl);

	if ((kpool = alloc_safe_mem(KPOOL_SZ)) == NULL) {
		fprintf(stderr, "Error allocating memory for keyfile pool\n");
		return ENOMEM;
	}

	memset(kpool, 0, KPOOL_SZ);

	for (k = 0; k < nkeyfiles; k++) {
#ifdef DEBUG
		printf("Loading keyfile %s into kpool\n", keyfiles[k]);
#endif
		kpool_idx = 0;
		crc = ~0U;
		kdata_sz = MAX_KFILE_SZ;

		if ((kdata = read_to_safe_mem(keyfiles[k], 0, &kdata_sz)) == NULL) {
			fprintf(stderr, "Error reading keyfile %s content\n",
			    keyfiles[k]);
			free_safe_mem(kpool);
			return EIO;
		}

		for (i = 0; i < kdata_sz; i++) {
			crc = crc32_intermediate(crc, kdata[i]);

			kpool[kpool_idx++] += (unsigned char)(crc >> 24);
			kpool[kpool_idx++] += (unsigned char)(crc >> 16);
			kpool[kpool_idx++] += (unsigned char)(crc >> 8);
			kpool[kpool_idx++] += (unsigned char)(crc);

			/* Wrap around */
			if (kpool_idx == KPOOL_SZ)
				kpool_idx = 0;
		}

		free_safe_mem(kdata);
	}

#ifdef DEBUG
	printf("Applying kpool to passphrase\n");
#endif
	/* Apply keyfile pool to passphrase */
	for (i = 0; i < KPOOL_SZ; i++)
		pass[i] += kpool[i];

	free_safe_mem(kpool);

	return 0;
}
