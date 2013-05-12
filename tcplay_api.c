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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "tcplay.h"
#include "tcplay_api.h"

int
tc_api_init(int verbose)
{
	int error;

	tc_internal_verbose = verbose;

	if ((error = tc_play_init()) != 0)
		return TC_ERR;
	else
		return TC_OK;
}

int
tc_api_uninit(void)
{
	check_and_purge_safe_mem();
	return TC_OK;
}

const char *
tc_api_get_error_msg(void)
{
	return tc_internal_log_buffer;
}

const char *
tc_api_get_summary(void)
{
	if (summary_fn != NULL) {
		summary_fn();
		return tc_internal_log_buffer;
	}

	return NULL;
}

tc_api_state
tc_api_get_state(float *progress)
{
	switch (tc_internal_state) {
	case STATE_UNKNOWN:
		return TC_STATE_UNKNOWN;

	case STATE_ERASE:
		if (progress != NULL)
			*progress = get_secure_erase_progress();
		return TC_STATE_ERASE;

	case STATE_GET_RANDOM:
		if (progress != NULL)
			*progress = get_random_read_progress();
		return TC_STATE_GET_RANDOM;

	default:
		return TC_STATE_UNKNOWN;
	}

}

int
tc_api_create_volume(tc_api_opts *api_opts)
{
	int nkeyfiles, n_hkeyfiles = 0;
	int create_hidden;
	int err;

	if ((api_opts == NULL) ||
	    (api_opts->tc_device == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	if ((err = tc_api_check_cipher(api_opts)) != TC_OK)
		return TC_ERR;

	if ((err = tc_api_check_prf_hash(api_opts)) != TC_OK)
		return TC_ERR;

	for (nkeyfiles = 0; (nkeyfiles < MAX_KEYFILES) &&
	    (api_opts->tc_keyfiles != NULL) &&
	    (api_opts->tc_keyfiles[nkeyfiles] != NULL); nkeyfiles++)
		;

	create_hidden = 0;

	if (api_opts->tc_size_hidden_in_bytes > 0) {
		create_hidden = 1;
		for (n_hkeyfiles = 0; (n_hkeyfiles < MAX_KEYFILES) &&
		    (api_opts->tc_keyfiles_hidden != NULL) &&
		    (api_opts->tc_keyfiles_hidden[n_hkeyfiles] != NULL);
		    n_hkeyfiles++)
			;
	}

	err = create_volume(api_opts->tc_device, create_hidden,
	    api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_keyfiles_hidden, n_hkeyfiles,
	    check_prf_algo(api_opts->tc_prf_hash, 1),
	    check_cipher_chain(api_opts->tc_cipher, 1),
	    api_opts->tc_prf_hash_hidden ? check_prf_algo(api_opts->tc_prf_hash_hidden, 1)   : NULL,
	    api_opts->tc_cipher_hidden   ? check_cipher_chain(api_opts->tc_cipher_hidden, 1) : NULL,
	    api_opts->tc_passphrase, api_opts->tc_passphrase_hidden,
	    api_opts->tc_size_hidden_in_bytes, 0 /* non-interactive */,
	    !api_opts->tc_no_secure_erase, api_opts->tc_use_weak_keys);

	return (err) ? TC_ERR : TC_OK;
}

int
tc_api_map_volume(tc_api_opts *api_opts)
{
	int nkeyfiles, n_hkeyfiles = 0;
	int err;

	if ((api_opts == NULL) ||
	    (api_opts->tc_map_name == NULL) ||
	    (api_opts->tc_device == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	for (nkeyfiles = 0; (nkeyfiles < MAX_KEYFILES) &&
	    (api_opts->tc_keyfiles != NULL) &&
	    (api_opts->tc_keyfiles[nkeyfiles] != NULL); nkeyfiles++)
		;

	if (api_opts->tc_protect_hidden) {
		for (n_hkeyfiles = 0; (n_hkeyfiles < MAX_KEYFILES) &&
		    (api_opts->tc_keyfiles_hidden != NULL) &&
		    (api_opts->tc_keyfiles_hidden[n_hkeyfiles] != NULL);
		    n_hkeyfiles++)
			;
	}

	err = map_volume(api_opts->tc_map_name, api_opts->tc_device,
	    api_opts->tc_use_system_encryption, api_opts->tc_system_device,
	    api_opts->tc_protect_hidden, api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_keyfiles_hidden, n_hkeyfiles,
	    api_opts->tc_passphrase, api_opts->tc_passphrase_hidden,
	    api_opts->tc_interactive_prompt, api_opts->tc_password_retries,
	    (time_t)api_opts->tc_prompt_timeout);

	return (err) ? TC_ERR : TC_OK;
}

int
tc_api_info_volume(tc_api_opts *api_opts, tc_api_volinfo *vol_info)
{
	struct tcplay_info *info;
	struct tc_cipher_chain *cipher_chain;
	int nkeyfiles, n_hkeyfiles = 0;
	int klen = 0;
	int n;

	if ((api_opts == NULL) ||
	    (vol_info == NULL) ||
	    (api_opts->tc_device == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	for (nkeyfiles = 0; (nkeyfiles < MAX_KEYFILES) &&
	    (api_opts->tc_keyfiles != NULL) &&
	    (api_opts->tc_keyfiles[nkeyfiles] != NULL); nkeyfiles++)
		;

	if (api_opts->tc_protect_hidden) {
		for (n_hkeyfiles = 0; (n_hkeyfiles < MAX_KEYFILES) &&
		    (api_opts->tc_keyfiles_hidden != NULL) &&
		    (api_opts->tc_keyfiles_hidden[n_hkeyfiles] != NULL);
		    n_hkeyfiles++)
			;
	}

	info = info_map_common(api_opts->tc_device,
	    api_opts->tc_use_system_encryption, api_opts->tc_system_device,
	    api_opts->tc_protect_hidden, api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_keyfiles_hidden, n_hkeyfiles,
	    api_opts->tc_passphrase, api_opts->tc_passphrase_hidden,
	    api_opts->tc_interactive_prompt, api_opts->tc_password_retries,
	    (time_t)api_opts->tc_prompt_timeout);

	if (info == NULL || info->hdr == NULL)
		return TC_ERR;

	for (cipher_chain = info->cipher_chain, n = 0;
	     cipher_chain != NULL;
	     cipher_chain = cipher_chain->next) {
		n += snprintf(vol_info->tc_cipher+n,
			      sizeof(vol_info->tc_cipher)-n,
			      "%s%s", cipher_chain->cipher->name,
			      (cipher_chain->next != NULL) ? "," : "");
		klen += cipher_chain->cipher->klen;
	}
	vol_info->tc_key_bits = 8*klen;
	strncpy(vol_info->tc_prf, info->pbkdf_prf->name, sizeof(vol_info->tc_prf));
	vol_info->tc_size = info->size * (off_t)info->hdr->sec_sz;
	vol_info->tc_iv_offset = info->skip * (off_t)info->hdr->sec_sz;
	vol_info->tc_block_offset = info->offset * (off_t)info->hdr->sec_sz;

	free_safe_mem(info->hdr);
	free_safe_mem(info);

	return TC_OK;
}

int
tc_api_unmap_volume(tc_api_opts *api_opts)
{
	int err;

	if ((api_opts == NULL) ||
	    (api_opts->tc_map_name == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	err = dm_teardown(api_opts->tc_map_name, api_opts->tc_device);
	return (err) ? TC_ERR : TC_OK;
}

int
tc_api_check_cipher(tc_api_opts *api_opts)
{
	struct tc_cipher_chain *chain;

	if (api_opts == NULL || api_opts->tc_cipher == NULL) {
		errno = EFAULT;
		return TC_ERR;
	}

	if ((chain = check_cipher_chain(api_opts->tc_cipher, 1)) != NULL)
		return TC_OK;

	errno = ENOENT;
	return TC_ERR;
}

int
tc_api_check_prf_hash(tc_api_opts *api_opts)
{
	struct pbkdf_prf_algo *prf_hash;

	if (api_opts == NULL || api_opts->tc_prf_hash == NULL) {
		errno = EFAULT;
		return TC_ERR;
	}

	if ((prf_hash = check_prf_algo(api_opts->tc_prf_hash, 1)) != NULL)
		return TC_OK;

	errno = ENOENT;
	return TC_ERR;
}

