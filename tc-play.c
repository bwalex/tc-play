/*
 * Copyright (c) 2011 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Alex Hornung <ahornung@gmail.com>
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
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
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
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/endian.h>
#include <sys/diskslice.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <uuid.h>
#include <termios.h>
#include <errno.h>
#include <time.h>
#include <libdevmapper.h>
#include <libutil.h>
#include <openssl/evp.h>

#include "crc32.h"
#include "tc-play.h"

#define alloc_safe_mem(x) \
	_alloc_safe_mem(x, __FILE__, __LINE__)

#define free_safe_mem(x) \
	_free_safe_mem(x, __FILE__, __LINE__)


/* XXX TODO:
 *  - LRW-benbi support? needs further work in dm-crypt and even opencrypto
 *  - secure buffer review (i.e: is everything that needs it using secure mem?)
 *  - mlockall? (at least MCL_FUTURE, which is the only one we support)
 *  - replace err(...) with r = 1; fprintf(); goto out;
 */

#if 0
/* Volume times:
 * return wxDateTime ((time_t) (volumeTime / 1000ULL / 1000 / 10 - 134774ULL * 24 * 3600));
 */
#define VOLTIME_TO_TIME(volumeTime) \
    ((time_t)(volumeTime / 1000ULL / 1000 / 10 - 134774ULL * 24 * 3600))

/*
Hi, dm-params:
0 261632 crypt aes-xts-plain64                                                                                                                                0 256 /dev/loop0 256

Hi, dm-params: 0 261632 crypt aes-xts-plain64 0 256 /dev/loop0 256
				256 = off_mk_scope / sec_sz!
		261632 = sz_mk_scope / sec_sz!

	 aes-cbc-essiv:sha256 7997f8af... 0 /dev/ad0s0a 8 
			         iv off---^  block off--^ 

Volume "/home/alex/tc-play/tctest.container" has been mounted.
*/

#endif

/* Version of tc-play */
#define MAJ_VER		0
#define MIN_VER		3

/* Comment out to disable debug info */
/* #define DEBUG		1 */

/* Endianess macros */
#define BE_TO_HOST(n, v) v = be ## n ## toh(v)
#define LE_TO_HOST(n, v) v = le ## n ## toh(v)
#define HOST_TO_BE(n, v) v = htobe ## n (v)
#define HOST_TO_LE(n, v) v = htobe ## n (v)


/* Supported algorithms */
struct pbkdf_prf_algo pbkdf_prf_algos[] = {
	{ "RIPEMD160",	2000 }, /* needs to come before the other RIPEMD160 */
	{ "RIPEMD160",	1000 },
	{ "SHA512",	1000 },
	{ "whirlpool",	1000 },
	{ NULL,		0    }
};

struct tc_crypto_algo tc_crypto_algos[] = {
	{ "AES-128-XTS",	"aes-xts-plain",	32,	8 },
	{ "AES-256-XTS",	"aes-xts-plain",	64,	8 },
	{ NULL,			NULL,			0,	0 }
};

int
hex2key(char *hex, size_t key_len, unsigned char *key)
{
	char hex_buf[3];
	size_t key_idx;
	hex_buf[2] = 0;
	for (key_idx = 0; key_idx < key_len; ++key_idx) {
		hex_buf[0] = *hex++;
		hex_buf[1] = *hex++;
		key[key_idx] = (unsigned char)strtoul(hex_buf, NULL, 16);
	}
	hex_buf[0] = 0;
	hex_buf[1] = 0;

	return 0;
}

#ifdef DEBUG
void
print_hex(unsigned char *buf, off_t start, size_t len)
{
	size_t i;

	for (i = start; i < start+len; i++)
		printf("%02x", buf[i]);

	printf("\n");
}
#endif

static struct safe_mem_hdr *safe_mem_hdr_first = NULL;

void *
_alloc_safe_mem(size_t req_sz, const char *file, int line)
{
	struct safe_mem_hdr *hdr, *hdrp;
	struct safe_mem_tail *tail;
	size_t alloc_sz;
	void *mem, *user_mem;

	alloc_sz = req_sz + sizeof(*hdr) + sizeof(*tail);
	if ((mem = malloc(alloc_sz)) == NULL)
		return NULL;

	if (mlock(mem, alloc_sz) < 0) {
		free(mem);
		return NULL;
	}

	memset(mem, 0, alloc_sz);

	hdr = (struct safe_mem_hdr *)mem;
	tail = (struct safe_mem_tail *)(mem + alloc_sz - sizeof(*tail));
	user_mem = mem + sizeof(*hdr);

	strcpy(hdr->sig, "SAFEMEM");
	strcpy(tail->sig, "SAFEMEM");
	hdr->tail = tail;
	hdr->alloc_sz = alloc_sz;
	hdr->file = file;
	hdr->line = line;

	if (safe_mem_hdr_first == NULL) {
		safe_mem_hdr_first = hdr;
	} else {
		hdrp = safe_mem_hdr_first;
		while (hdrp->next != NULL)
			hdrp = hdrp->next;
		hdr->prev = hdrp;
		hdrp->next = hdr;
	}

	return user_mem;
}

void
_free_safe_mem(void *mem, const char *file, int line)
{
	struct safe_mem_hdr *hdr;
	struct safe_mem_tail *tail;

	mem -= sizeof(*hdr);
	hdr = (struct safe_mem_hdr *)mem;
	tail = (struct safe_mem_tail *)(mem + hdr->alloc_sz - sizeof(*tail));

	if (hdr->alloc_sz == 0) {
		fprintf(stderr, "BUG: double-free at %s:%d !!!\n", file, line);
		exit(1);
	}

	/* Integrity checks */
	if ((memcmp(hdr->sig, "SAFEMEM\0", 8) != 0) ||
	    (memcmp(tail->sig, "SAFEMEM\0", 8) != 0)) {
		fprintf(stderr, "BUG: safe_mem buffer under- or overflow at "
		    "%s:%d !!!\n", file, line);
		exit(1);
	}

	if (safe_mem_hdr_first == NULL) {
		fprintf(stderr, "BUG: safe_mem list should not be empty at "
		    "%s:%d !!!\n", file, line);
		exit(1);
	}

	if (hdr->prev != NULL)
		hdr->prev->next = hdr->next;
	if (hdr->next != NULL)
		hdr->next->prev = hdr->prev;
	if (safe_mem_hdr_first == hdr)
		safe_mem_hdr_first = hdr->next;

	memset(mem, 0xFF, hdr->alloc_sz);
	memset(mem, 0, hdr->alloc_sz);

	free(mem);
}

void
check_and_purge_safe_mem(void)
{
	struct safe_mem_hdr *hdr, *hdrp;
	int ok;

	if (safe_mem_hdr_first == NULL)
		return;

	hdr = safe_mem_hdr_first;
	while (hdr != NULL) {
		if ((hdr->alloc_sz > 0) &&
		    (memcmp(hdr->sig, "SAFEMEM\0", 8) == 0) &&
		    (memcmp(hdr->tail->sig, "SAFEMEM\0", 8) == 0))
			ok = 1;
		else
			ok = 0;

#ifdef DEBUG
		fprintf(stderr, "un-freed safe_mem: %#lx (%s:%d) [integrity=%s]\n",
		    (unsigned long)(void *)hdr, hdr->file, hdr->line,
		    ok? "ok" : "failed");
#endif
		hdrp = hdr;
		hdr = hdr->next;
		free_safe_mem(hdrp);
	}
}

void *
read_to_safe_mem(const char *file, off_t offset, size_t *sz)
{
	void *mem = NULL;
	ssize_t r;
	int fd;

	if ((fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening file %s\n", file);
		return NULL;
	}

	if ((mem = alloc_safe_mem(*sz)) == NULL) {
		fprintf(stderr, "Error allocating memory\n");
		goto out;
	}

	if ((lseek(fd, offset, SEEK_SET) < 0)) {
		fprintf(stderr, "Error seeking on file %s\n", file);
		goto m_err;
	}

	if ((r = read(fd, mem, *sz)) <= 0) {
		fprintf(stderr, "Error reading from file %s\n", file);
		goto m_err;
	}

out:
	*sz = r;
	close(fd);
	return mem;
	/* NOT REACHED */

m_err:
	free_safe_mem(mem);
	close(fd);
	return NULL;
}

int
get_random(unsigned char *buf, size_t len)
{
	int fd;
	ssize_t r;
	size_t rd = 0;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; /* 10 ms */


	if ((fd = open("/dev/random", O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening /dev/random\n");
		return -1;
	}

	while (rd < len) {
		if ((r = read(fd, buf+rd, len-rd)) < 0) {
			fprintf(stderr, "Error reading from /dev/random\n");
			close(fd);
			return -1;
		}
		rd += r;
		nanosleep(&ts, NULL);
	}

	close(fd);
	return 0;
}

int
secure_erase(const char *dev, size_t bytes, size_t blksz)
{
	size_t erased = 0;
	int fd_rand, fd;
	char buf[MAX_BLKSZ];
	ssize_t r, w;

	if (blksz > MAX_BLKSZ) {
		fprintf(stderr, "blksz > MAX_BLKSZ\n");
		return -1;
	}

	if ((fd_rand = open("/dev/urandom", O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening /dev/urandom\n");
		return -1;
	}

	if ((fd = open(dev, O_WRONLY)) < 0) {
		close(fd_rand);
		fprintf(stderr, "Error opening %s\n", dev);
		return -1;
	}

	while (erased < bytes) {
		if ((r = read(fd_rand, buf, blksz)) < 0) {
			fprintf(stderr, "Error reading from /dev/urandom\n");
			close(fd);
			close(fd_rand);
			return -1;
		}

		if (r < blksz)
			continue;

		if ((w = write(fd, buf, blksz)) < 0) {
			fprintf(stderr, "Error writing to %s\n", dev);
			close(fd);
			close(fd_rand);
			return -1;
		}

		erased += (size_t)w;
	}

	close(fd);
	close(fd_rand);

	return 0;
}

int
get_disk_info(const char *dev, size_t *blocks, size_t *bsize)
{
	struct partinfo pinfo;
	int fd;

	if ((fd = open(dev, O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening %s\n", dev);
		return -1;
	}

	memset(&pinfo, 0, sizeof(struct partinfo));

	if (ioctl(fd, DIOCGPART, &pinfo) < 0) {
		close(fd);
		return -1;
	}

	*blocks = pinfo.media_blocks;
	*bsize = pinfo.media_blksize;

	close(fd);
	return 0;
}

int
tc_encrypt(const char *cipher_name, unsigned char *key, unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	const EVP_CIPHER *evp;
	EVP_CIPHER_CTX ctx;
	int outl, tmplen;

	evp = EVP_get_cipherbyname(cipher_name);
	if (evp == NULL) {
		printf("Cipher %s not found\n", cipher_name);
		return ENOENT;
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx, evp, key, iv);
	EVP_EncryptUpdate(&ctx, out, &outl, in, in_len);
	EVP_EncryptFinal(&ctx, out + outl, &tmplen);

	return 0;
}

int
tc_decrypt(const char *cipher_name, unsigned char *key, unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
	const EVP_CIPHER *evp;
	EVP_CIPHER_CTX ctx;
	int outl, tmplen;

	evp = EVP_get_cipherbyname(cipher_name);
	if (evp == NULL) {
		printf("Cipher %s not found\n", cipher_name);
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
read_passphrase(char *prompt, char *pass, size_t passlen)
{
	struct termios termios_old, termios_new;
	ssize_t n;
	int fd, r = 0, cfd = 0;

	if ((fd = open("/dev/tty", O_RDONLY)) == -1) {
		fd = STDIN_FILENO;
		cfd = 1;
	}

	printf(prompt);
	fflush(stdout);

	memset(pass, 0, passlen);

	tcgetattr(fd, &termios_old);
	memcpy(&termios_new, &termios_old, sizeof(termios_new));
	termios_new.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &termios_new);

	n = read(fd, pass, passlen-1);
	if (n > 0) {
		pass[n-1] = '\0'; /* Strip trailing \n */
	} else {
		r = EIO;
	}

	if (cfd)
		close(fd);

	tcsetattr(fd, TCSAFLUSH, &termios_old);
	putchar('\n');

	return r;
}

struct tchdr_dec *
decrypt_hdr(struct tchdr_enc *ehdr, char *algo, unsigned char *key)
{
	struct tchdr_dec *dhdr;
	unsigned char iv[128];
	int error;

	if ((dhdr = alloc_safe_mem(sizeof(struct tchdr_dec))) == NULL) {
		fprintf(stderr, "Error allocating safe tchdr_dec memory\n");
		return NULL;
	}

	memset(iv, 0, sizeof(iv));

	error = tc_decrypt(algo, key, iv, ehdr->enc, sizeof(struct tchdr_dec),
	    (unsigned char *)dhdr);
	if (error) {
		fprintf(stderr, "Header decryption failed\n");
		free_safe_mem(dhdr);
		return NULL;
	}

	BE_TO_HOST(16, dhdr->tc_ver);
	LE_TO_HOST(16, dhdr->tc_min_ver);
	BE_TO_HOST(32, dhdr->crc_keys);
	BE_TO_HOST(64, dhdr->vol_ctime);
	BE_TO_HOST(64, dhdr->hdr_ctime);
	BE_TO_HOST(64, dhdr->sz_hidvol);
	BE_TO_HOST(64, dhdr->sz_vol);
	BE_TO_HOST(64, dhdr->off_mk_scope);
	BE_TO_HOST(64, dhdr->sz_mk_scope);
	BE_TO_HOST(32, dhdr->flags);
	BE_TO_HOST(32, dhdr->sec_sz);
	BE_TO_HOST(32, dhdr->crc_dhdr);

	return dhdr;
}

int
verify_hdr(struct tchdr_dec *hdr)
{
	uint32_t crc;

	if (memcmp(hdr->tc_str, TC_SIG, sizeof(hdr->tc_str)) != 0) {
#ifdef DEBUG
		fprintf(stderr, "Signature mismatch\n");
#endif
		return 0;
	}

	crc = crc32((void *)&hdr->keys, 256);
	if (crc != hdr->crc_keys) {
#ifdef DEBUG
		fprintf(stderr, "CRC32 mismatch (crc_keys)\n");
#endif
		return 0;
	}

	switch(hdr->tc_ver) {
	case 1:
	case 2:
		/* Unsupported header version */
		fprintf(stderr, "Header version %d unsupported\n", hdr->tc_ver);
		return 0;

	case 3:
	case 4:
		hdr->sec_sz = 512;
		break;
	}

	return 1;
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

void
print_info(struct tcplay_info *info)
{
	printf("PBKDF2 PRF:\t\t%s\n", info->pbkdf_prf->name);
	printf("PBKDF2 iterations:\t%d\n", info->pbkdf_prf->iteration_count);
	printf("Cipher:\t\t\t%s\n", info->cipher->name);
	printf("Key Length:\t\t%d bits\n", info->cipher->klen*8);
	printf("CRC Key Data:\t\t%#x\n", info->hdr->crc_keys);
	printf("Sector size:\t\t%d\n", info->hdr->sec_sz);
	printf("Volume size:\t\t%d sectors\n", info->size);
}

struct tcplay_info *
new_info(const char *dev, struct tc_crypto_algo *cipher,
    struct pbkdf_prf_algo *prf, struct tchdr_dec *hdr, off_t start)
{
	struct tcplay_info *info;
	size_t i;

	if ((info = (struct tcplay_info *)alloc_safe_mem(sizeof(*info))) == NULL) {
		fprintf(stderr, "could not allocate safe info memory");
		return NULL;
	}

	info->dev = dev;
	info->cipher = cipher;
	info->pbkdf_prf = prf;
	info->start = start;
	info->hdr = hdr;
	info->size = hdr->sz_mk_scope / hdr->sec_sz;	/* volume size */
	info->skip = hdr->off_mk_scope / hdr->sec_sz;	/* iv skip */
	info->offset = hdr->off_mk_scope / hdr->sec_sz;	/* block offset */

	for (i = 0; i < cipher->klen; i++) {
		sprintf(&info->key[i*2], "%02x", hdr->keys[i]);
	}

	return info;
}

int
adjust_info(struct tcplay_info *info, struct tcplay_info *hinfo)
{
	if (hinfo->hdr->sz_hidvol == 0)
		return 1;

	info->size -= hinfo->hdr->sz_hidvol / hinfo->hdr->sec_sz;
	return 0;
}

int
process_hdr(const char *dev, unsigned char *pass, int passlen,
    struct tchdr_enc *ehdr, struct tcplay_info **pinfo)
{
	struct tchdr_dec *dhdr;
	struct tcplay_info *info;
	unsigned char *key;
	int i, j, found, error;

	*pinfo = NULL;

	if ((key = alloc_safe_mem(MAX_KEYSZ)) == NULL) {
		err(1, "could not allocate safe key memory");
	}

	/* Start search for correct algorithm combination */
	found = 0;
	for (i = 0; !found && pbkdf_prf_algos[i].name != NULL; i++) {
#ifdef DEBUG
		printf("\nTrying PRF algo %s (%d)\n", pbkdf_prf_algos[i].name,
		    pbkdf_prf_algos[i].iteration_count);
		printf("Salt: ");
		print_hex(ehdr->salt, 0, sizeof(ehdr->salt));
#endif
		error = pbkdf2(pass, passlen,
		    ehdr->salt, sizeof(ehdr->salt),
		    pbkdf_prf_algos[i].iteration_count,
		    pbkdf_prf_algos[i].name, MAX_KEYSZ, key);

		if (error)
			continue;

#if 0
		printf("Derived Key: ");
		print_hex(key, 0, MAX_KEYSZ);
#endif

		for (j = 0; !found && tc_crypto_algos[j].name != NULL; j++) {
#ifdef DEBUG
			printf("\nTrying cipher %s\n", tc_crypto_algos[j].name);
#endif

			dhdr = decrypt_hdr(ehdr, tc_crypto_algos[j].name, key);
			if (dhdr == NULL) {
				continue;
			}

			if (verify_hdr(dhdr)) {
#ifdef DEBUG
				printf("tc_str: %.4s, tc_ver: %zd, tc_min_ver: %zd, "
				    "crc_keys: %d, sz_vol: %"PRIu64", "
				    "off_mk_scope: %"PRIu64", sz_mk_scope: %"PRIu64", "
				    "flags: %d, sec_sz: %d crc_dhdr: %d\n",
				    dhdr->tc_str, dhdr->tc_ver, dhdr->tc_min_ver,
				    dhdr->crc_keys, dhdr->sz_vol, dhdr->off_mk_scope,
				    dhdr->sz_mk_scope, dhdr->flags, dhdr->sec_sz,
				    dhdr->crc_dhdr);
#endif
				found = 1;
			} else {
				free_safe_mem(dhdr);
			}
		}
	}

	free_safe_mem(key);

	if (!found)
		return EINVAL;

	if ((info = new_info(dev, &tc_crypto_algos[j-1], &pbkdf_prf_algos[i-1],
	    dhdr, 0)) == NULL) {
		return ENOMEM;
	}

	*pinfo = info;
	return 0;
}

int
write_hdr(const char *dev, off_t offset, size_t blksz, struct tchdr_enc *hdr)
{
	ssize_t w;
	int fd;

	if ((fd = open(dev, O_WRONLY)) < 0) {
		fprintf(stderr, "Error opening device %s\n", dev);
		return -1;
	}

	if ((lseek(fd, offset, SEEK_SET) < 0)) {
		fprintf(stderr, "Error seeking on device %s\n", dev);
		close(fd);
		return -1;
	}

	if ((w = write(fd, hdr, sizeof(*hdr))) <= 0) {
		fprintf(stderr, "Error writing to device %s\n", dev);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

struct tchdr_enc *
create_hdr(unsigned char *pass, int passlen, struct pbkdf_prf_algo *prf_algo,
    struct tc_crypto_algo *cipher, size_t sec_sz, size_t total_blocks,
    off_t offset, size_t blocks, int hidden)
{
	struct tchdr_enc *ehdr;
	struct tchdr_dec *dhdr;
	unsigned char *key;
	unsigned char iv[128];
	int error;

	if ((dhdr = (struct tchdr_dec *)alloc_safe_mem(sizeof(*dhdr))) == NULL) {
		fprintf(stderr, "could not allocate safe dhdr memory\n");
		return NULL;
	}

	if ((ehdr = (struct tchdr_enc *)alloc_safe_mem(sizeof(*ehdr))) == NULL) {
		fprintf(stderr, "could not allocate safe ehdr memory\n");
		return NULL;
	}

	if ((key = alloc_safe_mem(MAX_KEYSZ)) == NULL) {
		fprintf(stderr, "could not allocate safe key memory\n");
		return NULL;
	}

	if ((error = get_random(ehdr->salt, sizeof(ehdr->salt))) != 0) {
		fprintf(stderr, "could not get salt\n");
		return NULL;
	}

	error = pbkdf2(pass, passlen,
	    ehdr->salt, sizeof(ehdr->salt),
	    prf_algo->iteration_count,
	    prf_algo->name, MAX_KEYSZ, key);
	if (error) {
		fprintf(stderr, "could not derive key\n");
		return NULL;
	}

	memset(dhdr, 0, sizeof(*dhdr));

	if ((error = get_random(dhdr->keys, sizeof(dhdr->keys))) != 0) {
		fprintf(stderr, "could not get key random bits\n");
		return NULL;
	}

	memcpy(dhdr->tc_str, "TRUE", 4);
	dhdr->tc_ver = 5;
	dhdr->tc_min_ver = 7;
	dhdr->crc_keys = crc32((void *)&dhdr->keys, 256);
	dhdr->sz_vol = total_blocks * sec_sz;
	if (hidden)
		dhdr->sz_hidvol = dhdr->sz_vol;
	dhdr->off_mk_scope = offset * sec_sz;
	dhdr->sz_mk_scope = blocks * sec_sz;
	dhdr->sec_sz = sec_sz;
	dhdr->flags = 0;

	HOST_TO_BE(16, dhdr->tc_ver);
	HOST_TO_LE(16, dhdr->tc_min_ver);
	HOST_TO_BE(32, dhdr->crc_keys);
	HOST_TO_BE(64, dhdr->sz_vol);
	HOST_TO_BE(64, dhdr->sz_hidvol);
	HOST_TO_BE(64, dhdr->off_mk_scope);
	HOST_TO_BE(64, dhdr->sz_mk_scope);
	HOST_TO_BE(32, dhdr->sec_sz);
	HOST_TO_BE(32, dhdr->flags);

	dhdr->crc_dhdr = crc32((void *)dhdr, 188);
	HOST_TO_BE(32, dhdr->crc_dhdr);

	memset(iv, 0, sizeof(iv));
	error = tc_encrypt(cipher->name, key, iv, (unsigned char *)dhdr,
	    sizeof(struct tchdr_dec), ehdr->enc);
	if (error) {
		fprintf(stderr, "Header encryption failed\n");
		free_safe_mem(dhdr);
		return NULL;
	}

	free_safe_mem(dhdr);
	return ehdr;
}

int
create_volume(const char *dev, int hidden, const char *keyfiles[], int nkeyfiles,
    const char *h_keyfiles[], int n_hkeyfiles, struct pbkdf_prf_algo *prf_algo,
    struct tc_crypto_algo *cipher)
{
	char *pass;
	char *h_pass = NULL;
	char buf[1024];
	size_t blocks, blksz, hidden_blocks;
	struct tchdr_enc *ehdr, *hehdr;
	int error, r;

	if (cipher == NULL)
		cipher = &tc_crypto_algos[0];
	if (prf_algo == NULL)
		prf_algo = &pbkdf_prf_algos[0];

	if ((error = get_disk_info(dev, &blocks, &blksz)) != 0) {
		fprintf(stderr, "could not get disk info\n");
		return -1;
	}

	if (blocks <= MIN_VOL_BLOCKS) {
		fprintf(stderr, "Cannot create volumes on devices with less "
		    "than 256 blocks/sectors\n");
		return -1;
	}

	if ((pass = alloc_safe_mem(MAX_PASSSZ)) == NULL) {
		fprintf(stderr, "could not allocate safe passphrase memory\n");
		return -1;
	}

	if ((error = read_passphrase("Passphrase: ", pass, MAX_PASSSZ))) {
		fprintf(stderr, "could not read passphrase\n");
		return -1;
	}

	if (nkeyfiles > 0) {
		/* Apply keyfiles to 'pass' */
		if ((error = apply_keyfiles(pass, MAX_PASSSZ, keyfiles,
		    nkeyfiles))) {
			fprintf(stderr, "could not apply keyfiles\n");
		}
	}

	if (hidden) {
		if ((h_pass = alloc_safe_mem(MAX_PASSSZ)) == NULL) {
			fprintf(stderr, "could not allocate safe passphrase memory\n");
			return -1;
		}

		if ((error = read_passphrase("Passphrase for hidden volume: ",
		    h_pass, MAX_PASSSZ))) {
			fprintf(stderr, "could not read passphrase\n");
			return -1;
		}

		if (n_hkeyfiles > 0) {
			/* Apply keyfiles to 'h_pass' */
			if ((error = apply_keyfiles(h_pass, MAX_PASSSZ, h_keyfiles,
			n_hkeyfiles))) {
				fprintf(stderr, "could not apply keyfiles\n");
				return -1;
			}
		}

		hidden_blocks = 0;

		while(hidden_blocks == 0) {
			if ((r = humanize_number(buf, strlen("XXXX MB "),
			    (int64_t)(blocks * blksz), "B", 0, 0)) < 0) {
				sprintf(buf, "%zu bytes", (blocks * blksz));
			}

			printf("The total volume size of %s is %s (bytes)\n", dev, buf);
			memset(buf, 0, sizeof(buf));
			printf("Size of hidden volume (e.g. 127M): ");
			fflush(stdout);

			if ((fgets(buf, sizeof(buf), stdin)) == NULL) {
				fprintf(stderr, "Could not read from stdin\n");
				return -1;
			}

			/* get rid of trailing newline */
			buf[strlen(buf)-1] = '\0';
			if ((error = dehumanize_number(buf,
			    (int64_t *)&hidden_blocks)) != 0) {
				fprintf(stderr, "Could not interpret input: %s\n", buf);
				return -1;
			}

			hidden_blocks /= blksz;
			if (hidden_blocks >= blocks - MIN_VOL_BLOCKS) {
				fprintf(stderr, "Hidden volume needs to be "
				    "smaller than the outer volume\n");
				hidden_blocks = 0;
				continue;
			}
		}
	}

	/* Show summary and ask for confirmation */
	printf("Summary of actions:\n");
	printf(" - Completely erase *EVERYTHING* on %s\n", dev);
	printf(" - Create %svolume on %s\n", hidden?("outer "):" ", dev);
	if (hidden) {
		printf(" - Create hidden volume of %zu bytes at end of outer "
		    "volume\n",
		    hidden_blocks * blksz);
	}

	printf("\n Are you sure you want to proceed? (y/n)\n");
	if ((fgets(buf, sizeof(buf), stdin)) == NULL) {
		fprintf(stderr, "Could not read from stdin\n");
		return -1;
	}

	if ((buf[0] != 'y') && (buf[0] != 'Y')) {
		fprintf(stderr, "User cancelled action(s)\n");
		return -1;
	}

	/* erase volume */
	if ((error = secure_erase(dev, blocks * blksz, blksz)) != 0) {
		fprintf(stderr, "could not securely erase device %s\n", dev);
		return -1;
	}

	/* create encrypted headers */
	ehdr = create_hdr(pass, (nkeyfiles > 0)?MAX_PASSSZ:strlen(pass),
	    prf_algo, cipher, blksz, blocks, MIN_VOL_BLOCKS,
	    blocks-MIN_VOL_BLOCKS, 0);
	if (ehdr == NULL) {
		fprintf(stderr, "Could not create header\n");
		return -1;
	}

	if (hidden) {
		hehdr = create_hdr(h_pass,
		    (n_hkeyfiles > 0)?MAX_PASSSZ:strlen(h_pass), prf_algo, cipher,
		    blksz, blocks, blocks - hidden_blocks, hidden_blocks, 1);
		if (hehdr == NULL) {
			fprintf(stderr, "Could not create hidden volume header\n");
			return -1;
		}
	}

	if ((error = write_hdr(dev, 0, blksz, ehdr)) != 0) {
		fprintf(stderr, "Could not write volume header to device\n");
		return -1;
	}

	if (hidden) {
		if ((error = write_hdr(dev, HDR_OFFSET_HIDDEN, blksz, hehdr)) != 0) {
			fprintf(stderr, "Could not write hidden volume header to "
			    "device\n");
			return -1;
		}
	}

	return 0;
}

int
dm_setup(const char *mapname, struct tcplay_info *info)
{
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	char *params = NULL;
	char *uu;
	uint32_t status;
	int ret = 0;

	if ((params = alloc_safe_mem(512)) == NULL) {
		fprintf(stderr, "could not allocate safe parameters memory");
		return ENOMEM;
		
	}

	/* aes-cbc-essiv:sha256 7997f8af... 0 /dev/ad0s0a 8 */
	/*			   iv off---^  block off--^ */
	snprintf(params, 512, "%s %s %"PRIu64 " %s %"PRIu64,
	    info->cipher->dm_crypt_str, info->key,
	    info->skip, info->dev, info->offset);
#ifdef DEBUG
	printf("Params: %s\n", params);
#endif
	if ((dmt = dm_task_create(DM_DEVICE_CREATE)) == NULL) {
		fprintf(stderr, "dm_task_create failed\n");
		ret = -1;
		goto out;
	}

	if ((dm_task_set_name(dmt, mapname)) == 0) {
		fprintf(stderr, "dm_task_set_name failed\n");
		ret = -1;
		goto out;
	}

	uuid_create(&info->uuid, &status);
	if (status != uuid_s_ok) {
		fprintf(stderr, "uuid_create failed\n");
		ret = -1;
		goto out;
	}

	uuid_to_string(&info->uuid, &uu, &status);
	if (uu == NULL) {
		fprintf(stderr, "uuid_to_string failed\n");
		ret = -1;
		goto out;
	}

	if ((dm_task_set_uuid(dmt, uu)) == 0) {
		free(uu);
		fprintf(stderr, "dm_task_set_uuid failed\n");
		ret = -1;
		goto out;
	}
	free(uu);

	if ((dm_task_add_target(dmt, info->start, info->size, "crypt", params)) == 0) {
		fprintf(stderr, "dm_task_add_target failed\n");
		ret = -1;
		goto out;
	}

	if ((dm_task_run(dmt)) == 0) {
		fprintf(stderr, "dm_task_task_run failed\n");
		ret = -1;
		goto out;
	}

	if ((dm_task_get_info(dmt, &dmi)) == 0) {
		fprintf(stderr, "dm_task_get info failed\n");
		/* XXX: probably do more than just erroring out... */
		ret = -1;
		goto out;
	}

out:
	free_safe_mem(params);
	if (dmt)
		dm_task_destroy(dmt);

	return ret;
}

static
struct tc_crypto_algo *
check_cipher(char *cipher)
{
	int i, found = 0;

	for (i = 0; tc_crypto_algos[i].name != NULL; i++) {
		if (strcmp(cipher, tc_crypto_algos[i].name) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Valid ciphers are: ");
		for (i = 0; tc_crypto_algos[i].name != NULL; i++)
			fprintf(stderr, "%s ", tc_crypto_algos[i].name);
		fprintf(stderr, "\n");
		return NULL;
	}

	return &tc_crypto_algos[i];
}

static
struct pbkdf_prf_algo *
check_prf_algo(char *algo)
{
	int i, found = 0;

	for (i = 0; pbkdf_prf_algos[i].name != NULL; i++) {
		if (strcmp(algo, pbkdf_prf_algos[i].name) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Valid PBKDF PRF algorithms are: ");
		for (i = 0; pbkdf_prf_algos[i].name != NULL; i++)
			fprintf(stderr, "%s ", pbkdf_prf_algos[i].name);
		fprintf(stderr, "\n");
		return NULL;
	}

	return &pbkdf_prf_algos[i];
}

static
void
usage(void)
{
	fprintf(stderr,
	    "Usage: tc-play <command> [options]\n"
	    "Valid commands and its arguments are:\n"
	    " -c\n"
	    "\t Creates a new TC volume on the device specified by -d\n"
	    " -i\n"
	    "\t Gives information about the TC volume specified by -d\n"
	    " -m <mapping name>\n"
	    "\t Creates a dm-crypt mapping for the device specified by -d\n"
	    "Valid options and its arguments are:\n"
	    " -a <pbkdf prf algorithm>\n"
	    "\t specifies which hashing function to use for the PBKDF password derivation\n"
	    "\t when creating a new volume. To see valid options, specify -a help.\n"
	    " -b <cipher>\n"
	    "\t specifies which cipher to use when creating a new TC volume.\n"
	    "\t To see valid options, specify -a help\n"
	    " -d <device path>\n"
	    "\t specifies the path to the volume to operate on (e.g. /dev/da0s1)\n"
	    " -s <disk path>\n"
	    "\t specifies that the disk (e.g. /dev/da0) is using system encryption\n"
	    " -k <key file>\n"
	    "\t specifies a key file to use for the password derivation, can appear\n"
	    "\t multiple times.\n"
	    " -e\n"
	    "\t protect a hidden volume when mounting the outer volume\n"
	    " -f <key file>\n"
	    "\t specifies a key file to use for the hidden volume password derivation.\n"
	    "\t This option is only valid in combination with -e\n"
	    " -g\n"
	    "\t specifies that the newly created volume will contain a hidden volume.\n"
	    "\t Option is only valid when creating a new TC volume\n"
	    );

	exit(1);
}

static struct option longopts[] = {
	{ "create",		no_argument,		NULL, 'c' },
	{ "cipher",		required_argument,	NULL, 'b' },
	{ "hidden",		no_argument,		NULL, 'g' },
	{ "pbkdf-prf",		required_argument,	NULL, 'a' },
	{ "info",		no_argument,		NULL, 'i' },
	{ "map",		required_argument,	NULL, 'm' },
	{ "keyfile",		required_argument,	NULL, 'k' },
	{ "keyfile-hidden",	required_argument,	NULL, 'f' },
	{ "protect-hidden",	no_argument,		NULL, 'e' },
	{ "device",		required_argument,	NULL, 'd' },
	{ "system-encryption",	required_argument,	NULL, 's' },
	{ NULL,			0,			NULL, 0   },
};

int
main(int argc, char *argv[])
{
	const char *dev = NULL, *sys_dev = NULL, *map_name = NULL;
	const char *keyfiles[MAX_KEYFILES];
	const char *h_keyfiles[MAX_KEYFILES];
	char *pass;
	char *h_pass = NULL;
	struct tchdr_enc *ehdr, *hehdr = NULL;
	struct tcplay_info *info, *hinfo = NULL;
	int nkeyfiles;
	int n_hkeyfiles;
	int ch, error, error2, r = 0;
	int sflag = 0, iflag = 0, mflag = 0, hflag = 0, cflag = 0, hidflag = 0;
	struct pbkdf_prf_algo *prf = NULL;
	struct tc_crypto_algo *cipher = NULL;
	size_t sz;

	OpenSSL_add_all_algorithms();
	atexit(check_and_purge_safe_mem);

	nkeyfiles = 0;
	n_hkeyfiles = 0;

	while ((ch = getopt_long(argc, argv, "a:b:cd:ef:ik:m:s:v", longopts, NULL)) != -1) {
		switch(ch) {
		case 'a':
			if (prf != NULL)
				usage();
			if ((prf = check_prf_algo(optarg)) == NULL)
				usage();
			break;
		case 'b':
			if (cipher != NULL)
				usage();
			if ((cipher = check_cipher(optarg)) == NULL)
				usage();
			break;
		case 'c':
			cflag = 0;
			break;
		case 'd':
			dev = optarg;
			break;
		case 'e':
			hflag = 1;
			break;
		case 'f':
			h_keyfiles[n_hkeyfiles++] = optarg;
			break;
		case 'g':
			hidflag = 1;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'k':
			keyfiles[nkeyfiles++] = optarg;
			break;
		case 'm':
			mflag = 1;
			map_name = optarg;
			break;
		case 's':
			sflag = 1;
			sys_dev = optarg;
			break;
		case 'v':
			printf("tc-play v%d.%d\n", MAJ_VER, MIN_VER);
			exit(0);
			/* NOT REACHED */
		case 'h':
		case '?':
		default:
			usage();
			/* NOT REACHED */
		}
	}

	argc -= optind;
	argv += optind;

	/* Check arguments */
	if (!((mflag || iflag || cflag) && dev != NULL) ||
	    (mflag && iflag) ||
	    (mflag && cflag) ||
	    (cflag && iflag) ||
	    (hidflag && !cflag) ||
	    (sflag && (sys_dev == NULL)) ||
	    (mflag && (map_name == NULL)) ||
	    (!hflag && n_hkeyfiles > 0)) {
		usage();
		/* NOT REACHED */
	}

	if (cflag) {
		error = create_volume(dev, hidflag, keyfiles, nkeyfiles,
		    h_keyfiles, n_hkeyfiles, prf, cipher);
		if (error) {
			fprintf(stderr, "could not create new volume on %s\n", dev);
			exit(1);
		}
		exit(0);
		/* NOT REACHED */
	}

	/* This is only for iflag and mflag: */
	if ((pass = alloc_safe_mem(MAX_PASSSZ)) == NULL) {
		err(1, "could not allocate safe passphrase memory");
	}

	if ((error = read_passphrase("Passphrase: ", pass, MAX_PASSSZ))) {
		err(1, "could not read passphrase");
	}

	if (nkeyfiles > 0) {
		/* Apply keyfiles to 'pass' */
		if ((error = apply_keyfiles(pass, MAX_PASSSZ, keyfiles,
		    nkeyfiles))) {
			err(1, "could not apply keyfiles");
		}
	}

	if (hflag) {
		if ((h_pass = alloc_safe_mem(MAX_PASSSZ)) == NULL) {
			err(1, "could not allocate safe passphrase memory");
		}

		if ((error = read_passphrase("Passphrase for hidden volume: ",
		    h_pass, MAX_PASSSZ))) {
			err(1, "could not read passphrase");
		}

		if (n_hkeyfiles > 0) {
			/* Apply keyfiles to 'h_pass' */
			if ((error = apply_keyfiles(h_pass, MAX_PASSSZ, h_keyfiles,
			n_hkeyfiles))) {
				err(1, "could not apply keyfiles");
			}
		}
	}

	sz = HDRSZ;
	ehdr = (struct tchdr_enc *)read_to_safe_mem((sflag) ? sys_dev : dev,
	    (sflag) ? HDR_OFFSET_SYS : 0, &sz);
	if (ehdr == NULL) {
		err(1, "read hdr_enc: %s", dev);
	}

	if (!sflag) {
		sz = HDRSZ;
		hehdr = (struct tchdr_enc *)read_to_safe_mem(dev, HDR_OFFSET_HIDDEN, &sz);
		if (hehdr == NULL) {
			err(1, "read hdr_enc: %s", dev);
		}
	} else {
		hehdr = NULL;
	}

#if 0
	if ((error = process_hdr(dev, pass, (nkeyfiles > 0)?MAX_PASSSZ:strlen(pass),
	    ehdr, &info)) != 0) {
		if (hehdr) {
			if ((error = process_hdr(dev, pass, (nkeyfiles > 0)?MAX_PASSSZ:strlen(pass),
			hehdr, &info)) != 0) {
				free_safe_mem(hehdr);
				r = 1;
				fprintf(stderr, "Incorrect password or not a TrueCrypt volume\n");
				goto out;
			}
		} else {
			r = 1;
			fprintf(stderr, "Incorrect password or not a TrueCrypt volume\n");
			goto out;
		}
	}
#endif
	
	error = process_hdr(dev, pass, (nkeyfiles > 0)?MAX_PASSSZ:strlen(pass),
	    ehdr, &info);

	if (hehdr && (error || hflag)) {
		if (error) {
			error2 = process_hdr(dev, pass,
			    (nkeyfiles > 0)?MAX_PASSSZ:strlen(pass), hehdr,
			    &info);
		} else if (hflag) {
			error2 = process_hdr(dev, h_pass,
			    (n_hkeyfiles > 0)?MAX_PASSSZ:strlen(h_pass), hehdr,
			    &hinfo);
		}
	}

	if ((hflag && (error || error2)) || /* We need both to protect a h. vol */
	    (error && error2)) {
		fprintf(stderr, "Incorrect password or not a TrueCrypt volume\n");
		goto out;
	}

	if (hflag) {
		if (adjust_info(info, hinfo) != 0) {
			fprintf(stderr, "Could not protected hidden volume\n");
			goto out;
		}
	}

	if (iflag) {
		print_info(info);
	} else if (mflag) {
		if ((error = dm_setup(map_name, info)) != 0) {
			fprintf(stderr, "could not set up dm-crypt mapping");
			goto out;
		}
		printf("All ok!");
	}

out:
	free_safe_mem(ehdr);
	if (hehdr)
		free_safe_mem(hehdr);
	free_safe_mem(pass);
	if (h_pass)
		free_safe_mem(h_pass);
	if (info) {
		free_safe_mem(info->hdr);
		free_safe_mem(info);
	}
	if (hinfo) {
		free_safe_mem(hinfo->hdr);
		free_safe_mem(hinfo);
	}

	return r;
}
