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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <libdevmapper.h>
#include <libutil.h>

#include "crc32.h"
#include "tc-play.h"


/* XXX TODO:
 *  - LRW-benbi support? needs further work in dm-crypt and even opencrypto
 *  - secure buffer review (i.e: is everything that needs it using secure mem?)
 *  - mlockall? (at least MCL_FUTURE, which is the only one we support)
 */

/* Version of tc-play */
#define MAJ_VER		0
#define MIN_VER		7

static struct tc_crypto_algo *check_cipher(char *cipher);


/* Supported algorithms */
struct pbkdf_prf_algo pbkdf_prf_algos[] = {
	{ "RIPEMD160",	2000 }, /* needs to come before the other RIPEMD160 */
	{ "RIPEMD160",	1000 },
	{ "SHA512",	1000 },
	{ "whirlpool",	1000 },
	{ NULL,		0    }
};

struct tc_crypto_algo tc_crypto_algos[] = {
#if 0
	/* XXX: turns out TC doesn't support AES-128-XTS */
	{ "AES-128-XTS",	"aes-xts-plain",	32,	8 },
	{ "TWOFISH-128-XTS",	"twofish-xts-plain",	32,	8 },
	{ "SERPENT-128-XTS",	"serpent-xts-plain",	32,	8 },
#endif
	{ "AES-256-XTS",	"aes-xts-plain",	64,	8 },
	{ "TWOFISH-256-XTS",	"twofish-xts-plain",	64,	8 },
	{ "SERPENT-256-XTS",	"serpent-xts-plain",	64,	8 },
	{ NULL,			NULL,			0,	0 }
};

char *valid_cipher_chains[][MAX_CIPHER_CHAINS] = {
	{ "AES-256-XTS", NULL },
	{ "TWOFISH-256-XTS", NULL },
	{ "SERPENT-256-XTS", NULL },
	{ "AES-256-XTS", "TWOFISH-256-XTS", NULL },
	{ "AES-256-XTS", "TWOFISH-256-XTS", "SERPENT-256-XTS", NULL },
	{ "SERPENT-256-XTS", "AES-256-XTS", NULL },
	{ "SERPENT-256-XTS", "TWOFISH-256-XTS", "AES-256-XTS", NULL },
	{ "TWOFISH-256-XTS", "SERPENT-256-XTS", NULL },
	{ NULL }
};

struct tc_cipher_chain *tc_cipher_chains[MAX_CIPHER_CHAINS];

static
void
tc_build_cipher_chains(void)
{
	struct tc_cipher_chain *chain, *elem, *prev;
	int i = 0;
	int k;

	while (valid_cipher_chains[i][0] != NULL) {
		chain = NULL;
		prev = NULL;
		k = 0;

		while (valid_cipher_chains[i][k] != NULL) {
			if ((elem = alloc_safe_mem(sizeof(*elem))) == NULL) {
				fprintf(stderr, "Error allocating memory for "
				   "cipher chain\n");
				exit(1);
			}

			/* Initialize first element of chain */
			if (chain == NULL) {
				chain = elem;
				elem->prev = NULL;
			}

			/* Populate previous element */
			if (prev != NULL) {
				prev->next = elem;
				elem->prev = prev;
			}

			/* Assume we are the last element in the chain */
			elem->next = NULL;

			/* Initialize other fields */
			elem->cipher = check_cipher(valid_cipher_chains[i][k]);
			if (elem->cipher == NULL)
				exit(1);

			elem->key = NULL;

			prev = elem;
			++k;
		}

		/* Store cipher chain */
		tc_cipher_chains[i++] = chain;

		/* Integrity check */
		if (i >= MAX_CIPHER_CHAINS) {
			fprintf(stderr, "FATAL: tc_cipher_chains is full!!\n");
			exit(1);
		}

		/* Make sure array is NULL terminated */
		tc_cipher_chains[i] = NULL;
	}
}

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

void
print_info(struct tcplay_info *info)
{
	struct tc_cipher_chain *cipher_chain;
	int klen = 0;

	printf("PBKDF2 PRF:\t\t%s\n", info->pbkdf_prf->name);
	printf("PBKDF2 iterations:\t%d\n", info->pbkdf_prf->iteration_count);

	printf("Cipher:\t\t\t");
	for (cipher_chain = info->cipher_chain;
	    cipher_chain != NULL;
	    cipher_chain = cipher_chain->next) {
		printf("%s%c", cipher_chain->cipher->name,
		    (cipher_chain->next != NULL) ? ',' : '\n');
		klen += cipher_chain->cipher->klen;
	}

	printf("Key Length:\t\t%d bits\n", klen*8);
	printf("CRC Key Data:\t\t%#x\n", info->hdr->crc_keys);
	printf("Sector size:\t\t%d\n", info->hdr->sec_sz);
	printf("Volume size:\t\t%d sectors\n", info->size);
}

struct tcplay_info *
new_info(const char *dev, struct tc_cipher_chain *cipher_chain,
    struct pbkdf_prf_algo *prf, struct tchdr_dec *hdr, off_t start)
{
	struct tcplay_info *info;
	size_t i;
	int err;

	if ((info = (struct tcplay_info *)alloc_safe_mem(sizeof(*info))) == NULL) {
		fprintf(stderr, "could not allocate safe info memory\n");
		return NULL;
	}

	info->dev = dev;
	info->cipher_chain = cipher_chain;
	info->pbkdf_prf = prf;
	info->start = start;
	info->hdr = hdr;
	info->size = hdr->sz_mk_scope / hdr->sec_sz;	/* volume size */
	info->skip = hdr->off_mk_scope / hdr->sec_sz;	/* iv skip */
	info->offset = hdr->off_mk_scope / hdr->sec_sz;	/* block offset */

	err = tc_cipher_chain_populate_keys(cipher_chain, hdr->keys);
	if (err) {
		fprintf(stderr, "could not populate keys in cipher chain\n");
		return NULL;
	}

	for (; cipher_chain != NULL; cipher_chain = cipher_chain->next) {
		for (i = 0; i < cipher_chain->cipher->klen; i++)
			sprintf(&cipher_chain->dm_key[i*2], "%02x",
			    cipher_chain->key[i]);
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

		for (j = 0; !found && tc_cipher_chains[j] != NULL; j++) {
#ifdef DEBUG
			printf("\nTrying cipher chain %d\n", j);
#endif

			dhdr = decrypt_hdr(ehdr, tc_cipher_chains[j], key);
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

	if ((info = new_info(dev, tc_cipher_chains[j-1], &pbkdf_prf_algos[i-1],
	    dhdr, 0)) == NULL) {
		return ENOMEM;
	}

	*pinfo = info;
	return 0;
}

int
create_volume(const char *dev, int hidden, const char *keyfiles[], int nkeyfiles,
    const char *h_keyfiles[], int n_hkeyfiles, struct pbkdf_prf_algo *prf_algo,
    struct tc_cipher_chain *cipher_chain)
{
	char *pass;
	char *h_pass = NULL;
	char buf[1024];
	size_t blocks, blksz, hidden_blocks;
	struct tchdr_enc *ehdr, *hehdr;
	int error, r;

	if (cipher_chain == NULL)
		cipher_chain = tc_cipher_chains[0];
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
			if ((r = humanize_number(buf, strlen("XXX MB"),
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
	printf(" - Create %svolume on %s\n", hidden?("outer "):"", dev);
	if (hidden) {
		printf(" - Create hidden volume of %zu bytes at end of outer "
		    "volume\n",
		    hidden_blocks * blksz);
	}

	printf("\n Are you sure you want to proceed? (y/n) ");
	fflush(stdout);
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
	    prf_algo, cipher_chain, blksz, blocks, MIN_VOL_BLOCKS,
	    blocks-MIN_VOL_BLOCKS, 0);
	if (ehdr == NULL) {
		fprintf(stderr, "Could not create header\n");
		return -1;
	}

	if (hidden) {
		hehdr = create_hdr(h_pass,
		    (n_hkeyfiles > 0)?MAX_PASSSZ:strlen(h_pass), prf_algo,
		    cipher_chain,
		    blksz, blocks, blocks - hidden_blocks, hidden_blocks, 1);
		if (hehdr == NULL) {
			fprintf(stderr, "Could not create hidden volume header\n");
			return -1;
		}
	}

	if ((error = write_mem(dev, 0, blksz, ehdr, sizeof(*ehdr))) != 0) {
		fprintf(stderr, "Could not write volume header to device\n");
		return -1;
	}

	if (hidden) {
		if ((error = write_mem(dev, HDR_OFFSET_HIDDEN, blksz, hehdr,
		    sizeof(*hehdr))) != 0) {
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
	struct tc_cipher_chain *cipher_chain;
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	char *params = NULL;
	char *uu;
	uint32_t status;
	int ret = 0;
	int j;
	off_t start, offset;
	char dev[PATH_MAX];
	char map[PATH_MAX];

	if ((params = alloc_safe_mem(512)) == NULL) {
		fprintf(stderr, "could not allocate safe parameters memory");
		return ENOMEM;
	}

	strcpy(dev, info->dev);
	start = info->start;
	offset = info->offset;

	/* Get to the end of the chain */
	for (cipher_chain = info->cipher_chain; cipher_chain->next != NULL;
	    cipher_chain = cipher_chain->next)
		;

	for (j= 0; cipher_chain != NULL;
	    cipher_chain = cipher_chain->prev, j++) {
		/* aes-cbc-essiv:sha256 7997f8af... 0 /dev/ad0s0a 8 */
		/*			   iv off---^  block off--^ */
		snprintf(params, 512, "%s %s %"PRIu64 " %s %"PRIu64,
		    cipher_chain->cipher->dm_crypt_str, cipher_chain->dm_key,
		    info->skip, dev, offset);
#ifdef DEBUG
		printf("Params: %s\n", params);
#endif

		if ((dmt = dm_task_create(DM_DEVICE_CREATE)) == NULL) {
			fprintf(stderr, "dm_task_create failed\n");
			ret = -1;
			goto out;
		}

		/*
		 * If this is the last element in the cipher chain, use the
		 * final map name. Otherwise pick a secondary name...
		 */
		if (cipher_chain->prev == NULL)
			strcpy(map, mapname);
		else
			sprintf(map, "%s.%d", mapname, j);

		if ((dm_task_set_name(dmt, map)) == 0) {
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

		if ((dm_task_add_target(dmt, start, info->size, "crypt", params)) == 0) {
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

		offset = 0;
		start = 0;
		sprintf(dev, "/dev/mapper/%s.%d", mapname, j);

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
struct tc_cipher_chain *
check_cipher_chain(char *cipher_chain)
{
	int i,k, found = 0, nciphers = 0, mismatch = 0;
	char *ciphers[8];
	char *token;

	while ((token = strsep(&cipher_chain, ",")) != NULL)
		ciphers[nciphers++] = token;

	for (i = 0; valid_cipher_chains[i][0] != NULL; i++) {
		mismatch = 0;

		for (k = 0; (valid_cipher_chains[i][k] != NULL); k++) {
			/*
			 * If there are more ciphers in the chain than in the
			 * ciphers[] variable this is not the right chain.
			 */
			if (k == nciphers) {
				mismatch = 1;
				break;
			}

			if (strcmp(ciphers[k], valid_cipher_chains[i][k]) != 0)
				mismatch = 1;
		}

		/*
		 * If all ciphers matched and there are exactly nciphers,
		 * then we found the right cipher chain.
		 */
		if ((k == nciphers) && !mismatch) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Valid cipher chains are:\n");
		for (i = 0; valid_cipher_chains[i][0] != NULL; i++) {
			for (k = 0; valid_cipher_chains[i][k] != NULL; k++) {
				fprintf(stderr, "%s%c",
				    valid_cipher_chains[i][k],
				    (valid_cipher_chains[i][k+1] != NULL) ?
				    ',' : '\0');
			}
			fprintf(stderr, "\n");
		}

		return NULL;
	}

	return tc_cipher_chains[i];
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
	    " -c, --create\n"
	    "\t Creates a new TC volume on the device specified by -d or --device\n"
	    " -i, --info\n"
	    "\t Gives information about the TC volume specified by -d or --device\n"
	    " -m <mapping name>, --map=<mapping name>\n"
	    "\t Creates a dm-crypt mapping with the given name for the device\n"
	    "\t specified by -d or --device\n"
	    "\nValid options and its arguments for 'create' are:\n"
	    " -a <pbkdf prf algorithm>, --pbkdf-prf=<pbkdf prf algorithm>\n"
	    "\t specifies which hashing function to use for the PBKDF password\n"
	    "\t derivation when creating a new volume\n"
	    "\t To see valid options, specify -a help\n"
	    " -b <cipher>, --cipher=<cipher>\n"
	    "\t specifies which cipher to use when creating a new TC volume\n"
	    "\t To see valid options, specify -b help\n"
	    " -g, --hidden\n"
	    "\t specifies that the newly created volume will contain a hidden volume\n"
	    "\nValid options and its arguments for 'info' and 'map' are:\n"
	    " -e, --protect-hidden\n"
	    "\t protect a hidden volume when mounting the outer volume\n"
	    " -s <disk path>, --system-encryption=<disk path>\n"
	    "\t specifies that the disk (e.g. /dev/da0) is using system encryption\n"
	    "\nValid options and its arguments common to all commands are:\n"
	    " -d <device path>, --device=<device path>\n"
	    "\t specifies the path to the volume to operate on (e.g. /dev/da0s1)\n"
	    " -k <key file>, --keyfile=<key file>\n"
	    "\t specifies a key file to use for the password derivation, can appear\n"
	    "\t multiple times\n"
	    " -f <key file>, --keyfile-hidden=<key file>\n"
	    "\t specifies a key file to use for the hidden volume password derivation\n"
	    "\t This option is only valid in combination with -e, --protect-hidden\n"
	    "\t or -g, --hidden\n"
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
	{ "version",		no_argument,		NULL, 'v' },
	{ "help",		no_argument,		NULL, 'h' },
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
	struct tc_cipher_chain *cipher_chain = NULL;
	size_t sz;

	tc_build_cipher_chains();
	tc_crypto_init();
	atexit(check_and_purge_safe_mem);

	nkeyfiles = 0;
	n_hkeyfiles = 0;

	while ((ch = getopt_long(argc, argv, "a:b:cd:efgh:ik:m:s:v", longopts,
	    NULL)) != -1) {
		switch(ch) {
		case 'a':
			if (prf != NULL)
				usage();
			if ((prf = check_prf_algo(optarg)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(0);
				else
					usage();
			}
			break;
		case 'b':
			if (cipher_chain != NULL)
				usage();
			if ((cipher_chain = check_cipher_chain(optarg)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(0);
				else
					usage();
			}
			break;
		case 'c':
			cflag = 1;
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
		    h_keyfiles, n_hkeyfiles, prf, cipher_chain);
		if (error) {
			err(1, "could not create new volume on %s\n", dev);
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
		errx(1, "Incorrect password or not a TrueCrypt volume\n");
	}

	if (hflag) {
		if (adjust_info(info, hinfo) != 0) {
			errx(1, "Could not protected hidden volume\n");
		}
	}

	if (iflag) {
		print_info(info);
	} else if (mflag) {
		if ((error = dm_setup(map_name, info)) != 0) {
			err(1, "could not set up dm-crypt mapping");
		}
		printf("All ok!");
	}

	return r;
}
