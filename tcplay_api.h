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

#ifndef _TCPLAY_API_H
#define _TCPLAY_API_H

#include <stddef.h>

#define TC_OK	0
#define TC_ERR	-1

typedef enum tc_api_state {
	TC_STATE_UNKNOWN,
	TC_STATE_ERASE,
	TC_STATE_GET_RANDOM
} tc_api_state;

typedef struct tc_api_opts {
	/* Common fields */
	const char	*tc_device;
	const char	*tc_passphrase;
	const char	**tc_keyfiles;
	const char	*tc_passphrase_hidden;
	const char	**tc_keyfiles_hidden;

	/* Fields for mapping / info */
	const char	*tc_map_name;
	int		tc_protect_hidden;

	/* Fields for mapping / info / modify */
	int		tc_password_retries;
	int		tc_interactive_prompt;
	unsigned long	tc_prompt_timeout;
	int		tc_use_system_encryption;
	const char	*tc_system_device;
	int		tc_use_fde;
	int		tc_use_backup;
	int		tc_allow_trim;

	/* Fields for modify */
	const char	*tc_new_passphrase;
	const char	**tc_new_keyfiles;
	const char	*tc_new_prf_hash;
	int		tc_use_weak_salt;

	/* Fields for creation */
	const char	*tc_cipher;
	const char	*tc_prf_hash;
	const char	*tc_cipher_hidden;
	const char	*tc_prf_hash_hidden;
	uint64_t	tc_size_hidden_in_bytes;
	int		tc_no_secure_erase;
	int		tc_use_weak_keys;
} tc_api_opts;

typedef struct tc_api_volinfo {
	char		tc_device[1024];
	char		tc_cipher[256];
	char		tc_prf[64];

	int		tc_key_bits;

	uint64_t	tc_size;
	off_t		tc_iv_offset;
	off_t		tc_block_offset;
} tc_api_volinfo;

#ifdef __cplusplus
extern "C" {
#endif

int tc_api_init(int verbose);
int tc_api_uninit(void);
int tc_api_info_volume(tc_api_opts *api_opts, tc_api_volinfo *vol_info);
int tc_api_info_mapped_volume(tc_api_opts *api_opts, tc_api_volinfo *vol_info);
int tc_api_create_volume(tc_api_opts *api_opts);
int tc_api_modify_volume(tc_api_opts *api_opts);
int tc_api_map_volume(tc_api_opts *api_opts);
int tc_api_unmap_volume(tc_api_opts *api_opts);
int tc_api_check_cipher(tc_api_opts *api_opts);
int tc_api_check_prf_hash(tc_api_opts *api_opts);
const char *tc_api_get_error_msg(void);
const char *tc_api_get_summary(void);
tc_api_state tc_api_get_state(float *progress_pct);

#ifdef __cplusplus
}
#endif

#endif
