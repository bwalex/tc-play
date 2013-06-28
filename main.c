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
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "tcplay.h"

#ifndef SIGINFO
#define SIGINFO SIGUSR1
#endif

#define FLAG_LONG_FDE		0xff01
#define FLAG_LONG_USE_BACKUP	0xff02


static
void
sig_handler(int sig)
{
	if ((sig == SIGUSR1 || sig == SIGINFO) && (summary_fn != NULL))
		summary_fn();
}

static
void
usage(void)
{
	fprintf(stderr,
	    "usage: tcplay -c -d device [-g] [-z] [-w] [-a pbkdb_hash] [-b cipher]\n"
	    "              [-f keyfile_hidden] [-k keyfile] [-x pbkdf_hash] [-y cipher]\n"
	    "       tcplay -i -d device [-e] [-f keyfile_hidden] [-k keyfile]\n"
	    "              [-s system_device] [--fde]\n"
	    "       tcplay -m mapping -d device [-e] [-f keyfile_hidden] [-k keyfile]\n"
	    "              [-s system_device] [--fde]\n"
	    "       tcplay -j mapping\n"
	    "       tcplay -u mapping\n"
	    "       tcplay -h | -v\n"
	    "\n"
	    "Valid commands are:\n"
	    " -c, --create\n"
	    "\t Creates a new TC volume on the device specified by -d or --device.\n"
	    " -h, --help\n"
	    "\t Print help message and exit.\n"
	    " -i, --info\n"
	    "\t Gives information about the TC volume specified by -d or --device.\n"
	    " -j <mapping name>, --info-mapped=<mapping name>\n"
	    "\t Gives information about the mapped TC volume under the given mapping.\n"
	    " -m <mapping name>, --map=<mapping name>\n"
	    "\t Creates a dm-crypt mapping with the given name for the device\n"
	    "\t specified by -d or --device.\n"
	    " -u <mapping name>, --unmap=<mapping name>\n"
	    "\t Removes a dm-crypt mapping with the given name.\n"
	    " -v, --version\n"
	    "\t Print version message and exit.\n"
	    "\n"
	    "Valid options for --create are:\n"
	    " -a <pbkdf prf algorithm>, --pbkdf-prf=<pbkdf prf algorithm>\n"
	    "\t Specifies which hashing function to use for the PBKDF password\n"
	    "\t derivation when creating a new volume.\n"
	    "\t To see valid options, specify '-a help'.\n"
	    " -b <cipher>, --cipher=<cipher>\n"
	    "\t Specifies which cipher to use when creating a new TC volume.\n"
	    "\t To see valid options, specify '-b help'.\n"
	    " -g, --hidden\n"
	    "\t Specifies that the newly created volume will contain a hidden volume.\n"
	    " -x <pbkdf prf algorithm>, --pbkdf-prf=<pbkdf prf algorithm>\n"
	    "\t Specifies which hashing function to use for the PBKDF password\n"
	    "\t derivation when creating a new hidden volume.  By default, the\n"
	    "\t same as for the outer volume will be used.\n"
	    "\t To see valid options, specify '-x help'.\n"
	    " -y <cipher>, --cipher=<cipher>\n"
	    "\t Specifies which cipher to use when creating a new hidden volume.\n"
	    "\t By default, the same as for the outer volume will be used.\n"
	    "\t To see valid options, specify '-y help'.\n"
	    " -z, --insecure-erase\n"
	    "\t Skips the erase of the disk. Possible security hazard.\n"
	    " -w, --weak-keys\n"
	    "\t Uses a weak source of entropy (urandom) for key material.\n"
	    "\t WARNING: This is a REALLY REALLY bad idea for anything but\n"
	    "\t testing.\n"
	    "\n"
	    "Valid options for --info and --map are:\n"
	    " -e, --protect-hidden\n"
	    "\t Protect a hidden volume when mounting the outer volume.\n"
	    " -s <disk path>, --system-encryption=<disk path>\n"
	    "\t Specifies that the disk (e.g. /dev/da0) is using system encryption.\n"
	    "\t --fde\n"
	    "\t Specifies that the disk (e.g. /dev/da0) is using full disk encryption.\n"
	    "\t --use-backup\n"
	    "\t Uses the backup headers (at the end of the volume) instead of the\n"
	    "\t primary headers.\n"
	    "\t This is useful when your primary headers have been corrupted.\n"
	    "\n"
	    "Valid options common to all commands are:\n"
	    " -d <device path>, --device=<device path>\n"
	    "\t Specifies the path to the volume to operate on (e.g. /dev/da0s1).\n"
	    " -f <key file>, --keyfile-hidden=<key file>\n"
	    "\t Specifies a key file to use for the hidden volume password derivation.\n"
	    "\t This option is only valid in combination with -e, --protect-hidden\n"
	    "\t or -g, --hidden.\n"
	    " -k <key file>, --keyfile=<key file>\n"
	    "\t Specifies a key file to use for the password derivation, can appear\n"
	    "\t multiple times.\n"
	    );

	exit(EXIT_FAILURE);
}

static struct option longopts[] = {
	{ "create",		no_argument,		NULL, 'c' },
	{ "cipher",		required_argument,	NULL, 'b' },
	{ "cipher-hidden",	required_argument,	NULL, 'y' },
	{ "hidden",		no_argument,		NULL, 'g' },
	{ "pbkdf-prf",		required_argument,	NULL, 'a' },
	{ "pbkdf-prf-hidden",	required_argument,	NULL, 'x' },
	{ "info",		no_argument,		NULL, 'i' },
	{ "info-mapped",	required_argument,	NULL, 'j' },
	{ "map",		required_argument,	NULL, 'm' },
	{ "keyfile",		required_argument,	NULL, 'k' },
	{ "keyfile-hidden",	required_argument,	NULL, 'f' },
	{ "protect-hidden",	no_argument,		NULL, 'e' },
	{ "device",		required_argument,	NULL, 'd' },
	{ "system-encryption",	required_argument,	NULL, 's' },
	{ "fde",		no_argument,		NULL, FLAG_LONG_FDE },
	{ "use-backup",		no_argument,		NULL, FLAG_LONG_USE_BACKUP },
	{ "unmap",		required_argument,	NULL, 'u' },
	{ "version",		no_argument,		NULL, 'v' },
	{ "weak-keys",		no_argument,		NULL, 'w' },
	{ "insecure-erase",	no_argument,		NULL, 'z' },
	{ "help",		no_argument,		NULL, 'h' },
	{ NULL,			0,			NULL, 0   },
};

int
main(int argc, char *argv[])
{
	const char *dev = NULL, *sys_dev = NULL, *map_name = NULL;
	const char *keyfiles[MAX_KEYFILES];
	const char *h_keyfiles[MAX_KEYFILES];
	int nkeyfiles;
	int n_hkeyfiles;
	int ch, error;
	int flags = 0;
	int info_vol = 0, map_vol = 0, protect_hidden = 0,
	    unmap_vol = 0, info_map = 0,
	    create_vol = 0, contain_hidden = 0, use_secure_erase = 1,
	    use_weak_keys = 0;
	struct pbkdf_prf_algo *prf = NULL;
	struct tc_cipher_chain *cipher_chain = NULL;
	struct pbkdf_prf_algo *h_prf = NULL;
	struct tc_cipher_chain *h_cipher_chain = NULL;

	if ((error = tc_play_init()) != 0) {
		fprintf(stderr, "Initialization failed, exiting.");
		exit(EXIT_FAILURE);
	}

	atexit(check_and_purge_safe_mem);
	signal(SIGUSR1, sig_handler);
	signal(SIGINFO, sig_handler);

	nkeyfiles = 0;
	n_hkeyfiles = 0;

	while ((ch = getopt_long(argc, argv, "a:b:cd:ef:ghij:k:m:s:u:vwx:y:z",
	    longopts, NULL)) != -1) {
		switch(ch) {
		case 'a':
			if (prf != NULL)
				usage();
			if ((prf = check_prf_algo(optarg, 0)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(EXIT_SUCCESS);
				else
					usage();
				/* NOT REACHED */
			}
			break;
		case 'b':
			if (cipher_chain != NULL)
				usage();
			if ((cipher_chain = check_cipher_chain(optarg, 0)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(EXIT_SUCCESS);
				else
					usage();
				/* NOT REACHED */
			}
			break;
		case 'c':
			create_vol = 1;
			break;
		case 'd':
			dev = optarg;
			break;
		case 'e':
			protect_hidden = 1;
			break;
		case 'f':
			h_keyfiles[n_hkeyfiles++] = optarg;
			break;
		case 'g':
			contain_hidden = 1;
			break;
		case 'i':
			info_vol = 1;
			break;
		case 'j':
			info_map = 1;
			map_name = optarg;
			break;
		case 'k':
			keyfiles[nkeyfiles++] = optarg;
			break;
		case 'm':
			map_vol = 1;
			map_name = optarg;
			break;
		case 's':
			flags |= TC_FLAG_SYS;
			sys_dev = optarg;
			break;
		case 'u':
			unmap_vol = 1;
			map_name = optarg;
			break;
		case 'v':
			printf("tcplay v%d.%d\n", MAJ_VER, MIN_VER);
			exit(EXIT_SUCCESS);
			/* NOT REACHED */
		case 'w':
			fprintf(stderr, "WARNING: Using urandom as source of "
			    "entropy for key material is a really bad idea.\n");
			use_weak_keys = 1;
			break;
		case 'x':
			if (h_prf != NULL)
				usage();
			if ((h_prf = check_prf_algo(optarg, 0)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(EXIT_SUCCESS);
				else
					usage();
				/* NOT REACHED */
			}
			break;
		case 'y':
			if (h_cipher_chain != NULL)
				usage();
			if ((h_cipher_chain = check_cipher_chain(optarg, 0)) == NULL) {
				if (strcmp(optarg, "help") == 0)
					exit(EXIT_SUCCESS);
				else
					usage();
				/* NOT REACHED */
			}
			break;
		case 'z':
			use_secure_erase = 0;
			break;
		case FLAG_LONG_FDE:
			flags |= TC_FLAG_FDE;
			break;
		case FLAG_LONG_USE_BACKUP:
			flags |= TC_FLAG_BACKUP;
			break;
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
	if (!(((map_vol || info_vol || create_vol) && dev != NULL) ||
	    ((unmap_vol || info_map) && map_name != NULL)) ||
	    (TC_FLAG_SET(flags, SYS) && TC_FLAG_SET(flags, FDE)) ||
	    (map_vol && info_vol) ||
	    (map_vol && create_vol) ||
	    (unmap_vol && map_vol) ||
	    (unmap_vol && info_vol) ||
	    (unmap_vol && create_vol) ||
	    (create_vol && info_vol) ||
	    (contain_hidden && !create_vol) ||
	    (TC_FLAG_SET(flags, SYS) && (sys_dev == NULL)) ||
	    (map_vol && (map_name == NULL)) ||
	    (unmap_vol && (map_name == NULL)) ||
	    (!(protect_hidden || create_vol) && n_hkeyfiles > 0)) {
		usage();
		/* NOT REACHED */
	}

	/* Create a new volume */
	if (create_vol) {
		error = create_volume(dev, contain_hidden, keyfiles, nkeyfiles,
		    h_keyfiles, n_hkeyfiles, prf, cipher_chain, h_prf,
		    h_cipher_chain, NULL, NULL,
		    0, 1 /* interactive */,
		    use_secure_erase, use_weak_keys);
		if (error) {
			tc_log(1, "could not create new volume on %s\n", dev);
		}
	} else if (info_map) {
		error = info_mapped_volume(map_name, 1 /* interactive */);
	} else if (info_vol) {
		error = info_volume(dev, flags, sys_dev, protect_hidden,
		    keyfiles, nkeyfiles, h_keyfiles, n_hkeyfiles, NULL, NULL,
		    1 /* interactive */, DEFAULT_RETRIES, 0);
	} else if (map_vol) {
		error = map_volume(map_name,
		    dev, flags, sys_dev, protect_hidden,
		    keyfiles, nkeyfiles, h_keyfiles, n_hkeyfiles, NULL, NULL,
		    1 /* interactive */, DEFAULT_RETRIES, 0);
	} else if (unmap_vol) {
		error = dm_teardown(map_name, NULL);
	}

	return error;
}
