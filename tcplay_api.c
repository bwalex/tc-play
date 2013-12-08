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
#include <stdarg.h>

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
	int flags = 0;

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

	if (api_opts->tc_use_system_encryption)
		flags |= TC_FLAG_SYS;
	if (api_opts->tc_use_fde)
		flags |= TC_FLAG_FDE;
	if (api_opts->tc_use_backup)
		flags |= TC_FLAG_BACKUP;
	if (api_opts->tc_allow_trim)
		flags |= TC_FLAG_ALLOW_TRIM;

	err = map_volume(api_opts->tc_map_name, api_opts->tc_device,
	    flags, api_opts->tc_system_device,
	    api_opts->tc_protect_hidden, api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_keyfiles_hidden, n_hkeyfiles,
	    api_opts->tc_passphrase, api_opts->tc_passphrase_hidden,
	    api_opts->tc_interactive_prompt, api_opts->tc_password_retries,
	    (time_t)api_opts->tc_prompt_timeout, NULL, NULL);

	return (err) ? TC_ERR : TC_OK;
}

int
tc_api_info_volume(tc_api_opts *api_opts, tc_api_volinfo *vol_info)
{
	struct tcplay_info *info;
	int nkeyfiles, n_hkeyfiles = 0;
	int flags = 0;

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

	if (api_opts->tc_use_system_encryption)
		flags |= TC_FLAG_SYS;
	if (api_opts->tc_use_fde)
		flags |= TC_FLAG_FDE;
	if (api_opts->tc_use_backup)
		flags |= TC_FLAG_BACKUP;

	info = info_map_common(api_opts->tc_device,
	    flags, api_opts->tc_system_device,
	    api_opts->tc_protect_hidden, api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_keyfiles_hidden, n_hkeyfiles,
	    api_opts->tc_passphrase, api_opts->tc_passphrase_hidden,
	    api_opts->tc_interactive_prompt, api_opts->tc_password_retries,
	    (time_t)api_opts->tc_prompt_timeout, NULL, NULL, NULL);

	if (info == NULL || info->hdr == NULL)
		return TC_ERR;

	tc_cipher_chain_sprint(vol_info->tc_cipher, sizeof(vol_info->tc_cipher),
	    info->cipher_chain);
	vol_info->tc_key_bits = 8*tc_cipher_chain_klen(info->cipher_chain);
	strncpy(vol_info->tc_prf, info->pbkdf_prf->name, sizeof(vol_info->tc_prf));
	vol_info->tc_size = info->size * (off_t)info->hdr->sec_sz;
	vol_info->tc_iv_offset = info->skip * (off_t)info->hdr->sec_sz;
	vol_info->tc_block_offset = info->offset * (off_t)info->hdr->sec_sz;
	strncpy(vol_info->tc_device, info->dev, sizeof(vol_info->tc_device));
	vol_info->tc_device[sizeof(vol_info->tc_device)-1] = '\0';

	free_safe_mem(info->hdr);
	free_safe_mem(info);

	return TC_OK;
}

int
tc_api_info_mapped_volume(tc_api_opts *api_opts, tc_api_volinfo *vol_info)
{
	struct tcplay_info *info;

	if ((api_opts == NULL) ||
	    (vol_info == NULL) ||
	    (api_opts->tc_map_name == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	info = dm_info_map(api_opts->tc_map_name);
	if (info == NULL)
		return TC_ERR;

	tc_cipher_chain_sprint(vol_info->tc_cipher, sizeof(vol_info->tc_cipher),
	    info->cipher_chain);
	vol_info->tc_key_bits = 8*tc_cipher_chain_klen(info->cipher_chain);
	strncpy(vol_info->tc_prf, "(unknown)", sizeof(vol_info->tc_prf));
	vol_info->tc_size = info->size * (size_t)info->blk_sz;
	vol_info->tc_iv_offset = info->skip * (off_t)info->blk_sz;
	vol_info->tc_block_offset = info->offset * (off_t)info->blk_sz;
	strncpy(vol_info->tc_device, info->dev, sizeof(vol_info->tc_device));
	vol_info->tc_device[sizeof(vol_info->tc_device)-1] = '\0';

	free_safe_mem(info);

	return TC_OK;
}

int
tc_api_modify_volume(tc_api_opts *api_opts)
{
	struct pbkdf_prf_algo *prf_hash = NULL;
	int nkeyfiles, n_newkeyfiles = 0;
	int flags = 0;
	int error;

	if ((api_opts == NULL) ||
	    (api_opts->tc_device == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	if (api_opts->tc_new_prf_hash != NULL) {
		if ((prf_hash = check_prf_algo(api_opts->tc_new_prf_hash, 1)) == NULL) {
			errno = EINVAL;
			return TC_ERR;
		}
	}

	for (nkeyfiles = 0; (nkeyfiles < MAX_KEYFILES) &&
	    (api_opts->tc_keyfiles != NULL) &&
	    (api_opts->tc_keyfiles[nkeyfiles] != NULL); nkeyfiles++)
		;

	for (n_newkeyfiles = 0; (n_newkeyfiles < MAX_KEYFILES) &&
	    (api_opts->tc_new_keyfiles != NULL) &&
	    (api_opts->tc_new_keyfiles[n_newkeyfiles] != NULL); n_newkeyfiles++)
		;

	if (api_opts->tc_use_system_encryption)
		flags |= TC_FLAG_SYS;
	if (api_opts->tc_use_fde)
		flags |= TC_FLAG_FDE;
	if (api_opts->tc_use_backup)
		flags |= TC_FLAG_BACKUP;

	error = modify_volume(api_opts->tc_device,
	    flags, api_opts->tc_system_device,
	    api_opts->tc_keyfiles, nkeyfiles,
	    api_opts->tc_new_keyfiles, n_newkeyfiles,
	    prf_hash,
	    api_opts->tc_passphrase, api_opts->tc_new_passphrase,
	    api_opts->tc_interactive_prompt, api_opts->tc_password_retries,
	    (time_t)api_opts->tc_prompt_timeout, api_opts->tc_use_weak_salt,
	    NULL, NULL, NULL);

	if (error)
		return TC_ERR;

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


tc_api_opts
tc_api_opts_init(void)
{
	struct tc_api_opts *opts = NULL;
	int fail = 1;

	if ((opts = alloc_safe_mem(sizeof(*opts))) == NULL) {
		errno = ENOMEM;
		goto out;
	}

	opts->opts = NULL;

	if ((opts->opts = opts_init()) == NULL) {
		errno = ENOMEM;
		goto out;
	}

	fail = 0;

out:
	if (opts != NULL) {
		if (opts->opts != NULL)
			opts_free(opts->opts);
		free_safe_mem(opts);
	}

	return fail ? NULL : opts;
}

int
tc_api_opts_uninit(tc_api_opts opts)
{
	opts_free(opts->opts);
	free_safe_mem(opts);
}

#define _match(k, v) (strcmp(k, v) == 0)

#define _set_str(k) \
	do {							\
		if ((opts->k = strdup_safe_mem(s)) == NULL) {	\
			errno = ENOMEM;				\
			r = TC_ERR;				\
			goto out;				\
		}						\
	} while (0)

#define _clr_str(k) \
	do {							\
		if (opts->k)					\
			free_safe_mem(opts->k);			\
		opts->k = NULL;					\
	} while (0)

int
tc_api_opts_set(tc_api_opts api_opts, const char *key, ...)
{
	struct tcplay_opts *opts;
	va_list ap;
	const char *s;
	int64_t i64;
	int i;
	int r = TC_OK;

	if (api_opts == NULL || ((opts = api_opts->opts) == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	va_start(ap, key);

	if (_match(key, "interactive")) {
		i = va_arg(ap, int);
		opts->interactive = i;
	} else if (_match(key, "weak_keys_and_salt")) {
		i = va_arg(ap, int);
		opts->weak_keys_and_salt = i;
	} else if (_match(key, "hidden")) {
		i = va_arg(ap, int);
		opts->hidden = i;
	} else if (_match(key, "secure_erase")) {
		i = va_arg(ap, int);
		opts->secure_erase = i;
	} else if (_match(key, "protect_hidden")) {
		i = va_arg(ap, int);
		opts->protect_hidden = i;
	} else if (_match(key, "fde")) {
		i = va_arg(ap, int);
		if (i)
			opts->flags |= TC_FLAG_FDE;
		else
			opts->flags &= ~TC_FLAG_FDE;
	} else if (_match(key, "use_backup_header")) {
		i = va_arg(ap, int);
		if (i)
			opts->flags |= TC_FLAG_BACKUP;
		else
			opts->flags &= ~TC_FLAG_BACKUP;
	} else if (_match(key, "allow_trim")) {
		i = va_arg(ap, int);
		if (i)
			opts->flags |= TC_FLAG_ALLOW_TRIM;
		else
			opts->flags &= ~TC_FLAG_ALLOW_TRIM;
	} else if (_match(key, "hidden_size_bytes")) {
		i64 = va_arg(ap, int64_t);
		opts->hidden_size_bytes = (disksz_t)i64;
	} else if (_match(key, "retries")) {
		i = va_arg(ap, int);
		opts->retries = i;
	} else if (_match(key, "timeout")) {
		i = va_arg(ap, int);
		opts->timeout = (time_t)i;
	} else if (_match(key, "save_header_to_file")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(hdr_file_out);
			opts->flags |= TC_FLAG_SAVE_TO_FILE;
		} else {
			_clr_str(hdr_file_out);
			opts->flags &= ~TC_FLAG_SAVE_TO_FILE;
		}
	} else if (_match(key, "header_from_file")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(hdr_file_in);
			opts->flags |= TC_FLAG_HDR_FROM_FILE;
		} else {
			_clr_str(hdr_file_in);
			opts->flags &= ~TC_FLAG_HDR_FROM_FILE;
		}
	} else if (_match(key, "hidden_header_from_file")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(h_hdr_file_in);
			opts->flags |= TC_FLAG_H_HDR_FROM_FILE;
		} else {
			_clr_str(h_hdr_file_in);
			opts->flags &= ~TC_FLAG_H_HDR_FROM_FILE;
		}
	} else if (_match(key, "sys")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(sys_dev);
			opts->flags |= TC_FLAG_SYS;
		} else {
			_clr_str(sys_dev);
			opts->flags &= ~TC_FLAG_SYS;
		}
	} else if (_match(key, "passphrase")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(passphrase);
		} else {
			_clr_str(passphrase);
		}
	} else if (_match(key, "h_passphrase")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(h_passphrase);
		} else {
			_clr_str(h_passphrase);
		}
	} else if (_match(key, "new_passphrase")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(new_passphrase);
		} else {
			_clr_str(new_passphrase);
		}
	} else if (_match(key, "dev")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(dev);
		} else {
			_clr_str(dev);
		}
	} else if (_match(key, "map_name")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			_set_str(map_name);
		} else {
			_clr_str(map_name);
		}
	} else if (_match(key, "keyfiles")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			opts_add_keyfile(opts, s);
		} else {
			opts_clear_keyfile(opts);
		}
	} else if (_match(key, "h_keyfiles")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			opts_add_keyfile_hidden(opts, s);
		} else {
			opts_clear_keyfile_hidden(opts);
		}
	} else if (_match(key, "new_keyfiles")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			opts_add_keyfile_new(opts, s);
		} else {
			opts_clear_keyfile_new(opts);
		}
	} else if (_match(key, "prf_algo")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			if ((opts->prf_algo = check_prf_algo(s, 1)) == NULL) {
				errno = ENOENT;
				r = TC_ERR;
				goto out;
			}
		} else {
			opts->prf_algo = NULL;
		}
	} else if (_match(key, "h_prf_algo")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			if ((opts->h_prf_algo = check_prf_algo(s, 1)) == NULL) {
				errno = ENOENT;
				r = TC_ERR;
				goto out;
			}
		} else {
			opts->h_prf_algo = NULL;
		}
	} else if (_match(key, "new_prf_algo")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			if ((opts->new_prf_algo = check_prf_algo(s, 1)) == NULL) {
				errno = ENOENT;
				r = TC_ERR;
				goto out;
			}
		} else {
			opts->new_prf_algo = NULL;
		}
	} else if (_match(key, "cipher_chain")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			if ((opts->cipher_chain = check_cipher_chain(s, 1)) == NULL) {
				errno = ENOENT;
				r = TC_ERR;
				goto out;
			}
		} else {
			opts->cipher_chain = NULL;
		}
	} else if (_match(key, "h_cipher_chain")) {
		s = va_arg(ap, const char *);
		if (s != NULL) {
			if ((opts->h_cipher_chain = check_cipher_chain(s, 1)) == NULL) {
				errno = ENOENT;
				r = TC_ERR;
				goto out;
			}
		} else {
			opts->h_cipher_chain = NULL;
		}
	} else {
		r = TC_ERR_UNIMPL;
	}

out:
	va_end(ap);

	return r;
}


int
tc_api_do(const char *op, tc_api_opts api_opts)
{
	struct tcplay_opts *opts;
	int r = TC_OK;

	if (api_opts == NULL || ((opts = api_opts->opts) == NULL)) {
		errno = EFAULT;
		return TC_ERR;
	}

	if (api_opts->last_info != NULL) {
		free_info(api_opts->last_info);
	}

	if (_match(op, "create")) {
		r = create_volume(opts);
	} else if (_match(op, "map")) {
		r = map_volume(opts);
	} else if (_match(op, "unmap")) {
		r = dm_teardown(opts->map_name, opts->dev);
	} else if (_match(op, "info")) {
		if ((api_opts->last_info = info_map_common(opts, NULL)) == NULL) {
			r = TC_ERR;
		}
	} else if (_match(op, "info_mapped")) {
		if ((api_opts->last_info = dm_info_map(opts)) == NULL) {
			r = TC_ERR;
		}
	} else if (_match(op, "modify")) {
		r = modify_volume(opts);
	} else if (_match(op, "restore")) {
		opts->flags |= TC_FLAG_ONLY_RESTORE;
		r = modify_volume(opts);
		opts->flags &= ~TC_FLAG_ONLY_RESTORE;
	} else {
		r = TC_ERR_UNIMPL;
	}

	return r;
}

/* XXX: free_cipher_chain calls to opts cleanups here and in tcplay.c */
/* XXX: free_info calls here in uninit */
