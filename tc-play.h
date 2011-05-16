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
#define MAX_BLKSZ		4096
#define MAX_KEYSZ		192
#define HDRSZ			512
#define HDR_OFFSET_SYS		31744	/* 512 * (63 -1) */
#define TC_SIG			"TRUE"
#define MAX_PASSSZ		64
#define KPOOL_SZ		64
#define MAX_KFILE_SZ		1048576	/* 1 MB */
#define MAX_KEYFILES		256
#define HDR_OFFSET_HIDDEN	65536
#define SALT_LEN		64
#define MIN_VOL_BLOCKS		256

/* TrueCrypt Volume flags */
#define TC_VOLFLAG_SYSTEM	0x01	/* system encryption */
#define TC_VOLFLAG_INPLACE	0x02	/* non-system in-place-encrypted volume */


struct pbkdf_prf_algo {
	char *name;
	int iteration_count;
};

struct tc_crypto_algo {
	char *name;
	char *dm_crypt_str;
	int klen;
	int ivlen;
};

struct tchdr_enc {
	unsigned char salt[SALT_LEN];	/* Salt for PBKDF */
	unsigned char enc[448];		/* Encrypted part of the header */
} __attribute__((__packed__));

struct tchdr_dec {
	char		tc_str[4];	/* ASCII string "TRUE" */
	uint16_t	tc_ver;		/* Volume header format version */
	uint16_t	tc_min_ver;
	uint32_t	crc_keys;	/* CRC32 of the key section */
	uint64_t	vol_ctime;	/* Volume creation time */
	uint64_t	hdr_ctime;	/* Header creation time */
	uint64_t	sz_hidvol;	/*  Size of hidden volume (set to zero
					    in non-hidden volumes) */
	uint64_t	sz_vol;		/*  Size of volume */
	uint64_t	off_mk_scope;	/*  Byte offset of the start of the
					    master key scope */
	uint64_t	sz_mk_scope;	/*  Size of the encrypted area within
					    the master key scope */
	uint32_t	flags;		/*  Flag bits
					    (bit 0: system encryption;
					    bit 1: non-system in-place-encrypted volume;
					    bits 2–31 are reserved) */
	uint32_t	sec_sz;		/*  Sector size (in bytes) */
	unsigned char	unused3[120];
	uint32_t	crc_dhdr;	/* CRC32 of dec. header (except keys) */
	unsigned char	keys[256];
} __attribute__((__packed__));

struct tcplay_info {
	const char *dev;
	struct tchdr_dec *hdr;
	struct tc_crypto_algo *cipher;
	struct pbkdf_prf_algo *pbkdf_prf;
	char key[MAX_KEYSZ*2];
	off_t start;	/* Logical volume offset in table */
	size_t size;	/* Volume size */

	off_t skip;	/* IV offset */
	off_t offset;	/* Block offset */

	/* Populated by dm_setup */
	uuid_t uuid;
};

struct safe_mem_hdr {
	struct safe_mem_hdr	*prev;
	struct safe_mem_hdr	*next;
	struct safe_mem_tail	*tail;
	const char	*file;
	int 		line;
	size_t		alloc_sz;
	char		sig[8]; /* SAFEMEM */
};

struct safe_mem_tail {
	char sig[8]; /* SAFEMEM */
};
