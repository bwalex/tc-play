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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <crypto/cryptodev.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/evp.h>

#include "crc32.h"
#include "tc-play.h"

static
int
getallowsoft(void)
{
	int old;
	size_t olen;

	olen = sizeof(old);

	if (sysctlbyname("kern.cryptodevallowsoft", &old, &olen, NULL, 0) < 0) {
		perror("accessing sysctl kern.cryptodevallowsoft failed");
	}

	return old;
}

static
void
setallowsoft(int new)
{
	int old;
	size_t olen, nlen;

	olen = nlen = sizeof(new);

	if (sysctlbyname("kern.cryptodevallowsoft", &old, &olen, &new, nlen) < 0) {
		perror("accessing sysctl kern.cryptodevallowsoft failed");
	}
}

static
int
syscrypt(int cipher, unsigned char *key, size_t klen, unsigned char *iv,
    unsigned char *in, unsigned char *out, size_t len, int do_encrypt)
{
	struct session_op session;
	struct crypt_op cryp;
	int cryptodev_fd = -1, fd = -1;

	if ((cryptodev_fd = open("/dev/crypto", O_RDWR, 0)) < 0) {
		perror("Could not open /dev/crypto");
		goto err;
	}
	if (ioctl(cryptodev_fd, CRIOGET, &fd) == -1) {
		perror("CRIOGET failed");
		goto err;
	}
	memset(&session, 0, sizeof(session));
	session.cipher = cipher;
	session.key = (caddr_t) key;
	session.keylen = klen;
	if (ioctl(fd, CIOCGSESSION, &session) == -1) {
		perror("CIOCGSESSION failed");
		goto err;
	}
	memset(&cryp, 0, sizeof(cryp));
	cryp.ses = session.ses;
	cryp.op = do_encrypt ? COP_ENCRYPT : COP_DECRYPT;
	cryp.flags = 0;
	cryp.len = len;
	cryp.src = (caddr_t) in;
	cryp.dst = (caddr_t) out;
	cryp.iv = (caddr_t) iv;
	cryp.mac = 0;
	if (ioctl(fd, CIOCCRYPT, &cryp) == -1) {
		perror("CIOCCRYPT failed");
		goto err;
	}
	if (ioctl(fd, CIOCFSESSION, &session.ses) == -1) {
		perror("CIOCFSESSION failed");
		goto err;
	}
	close(fd);
	close(cryptodev_fd);
	return (0);

err:
	if (fd != -1)
		close(fd);
	if (cryptodev_fd != -1)
		close(cryptodev_fd);
	return (-1);
}

static
int
get_cryptodev_cipher_id(struct tc_crypto_algo *cipher)
{
	if (strcmp(cipher->name, "AES-128-XTS") == 0)
		return CRYPTO_AES_XTS;
	else if (strcmp(cipher->name, "AES-256-XTS") == 0)
		return CRYPTO_AES_XTS;
	else
		return -1;
}

int
tc_crypto_init(void)
{
	int allowed;

	OpenSSL_add_all_algorithms();

	allowed = getallowsoft();
	if (allowed == 0)
		setallowsoft(1);

	return 0;
}

int
tc_encrypt(struct tc_crypto_algo *cipher, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	int cipher_id;

	cipher_id = get_cryptodev_cipher_id(cipher);
	if (cipher_id < 0) {
		fprintf(stderr, "Cipher %s not found\n", cipher->name);
		return ENOENT;
	}

	return syscrypt(cipher_id, key, cipher->klen, iv, in, out, in_len, 1);
}

int
tc_decrypt(struct tc_crypto_algo *cipher, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	int cipher_id;

	cipher_id = get_cryptodev_cipher_id(cipher);
	if (cipher_id < 0) {
		fprintf(stderr, "Cipher %s not found\n", cipher->name);
		return ENOENT;
	}

	return syscrypt(cipher_id, key, cipher->klen, iv, in, out, in_len, 0);
}

int
pbkdf2(const char *pass, int passlen, const unsigned char *salt, int saltlen,
    int iter, const char *hash_name, int keylen, unsigned char *out)
{
	const EVP_MD *md;
	int r;

	md = EVP_get_digestbyname(hash_name);
	if (md == NULL) {
		printf("Hash %s not found\n", hash_name);
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
