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
#include <time.h>
#include <libutil.h>

#include "tc-play.h"

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

	tc_play_init();

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
