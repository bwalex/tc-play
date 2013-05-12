require 'ffi'

module TCplayLib
  extend FFI::Library

  ffi_lib [ "../libtcplay.so.1.0" ]

  TC_OK  = 0
  TC_ERR = -1

  class TCApiOpts < FFI::Struct
    # Common fields
    layout :tc_device,                :pointer,
           :tc_passphrase,            :pointer,
           :tc_keyfiles,              :pointer,
           :tc_passphrase_hidden,     :pointer,
           :tc_keyfiles_hidden,       :pointer,

    # Fields for mapping / info
           :tc_map_name,              :pointer,
           :tc_protect_hidden,        :int,
           :tc_password_retries,      :int,
           :tc_interactive_prompt,    :int,
           :tc_prompt_timeout,        :ulong,
           :tc_use_system_encryption, :int,
           :tc_system_device,         :pointer,

    # Fields for creation
           :tc_cipher,                :pointer,
           :tc_prf_hash,              :pointer,
           :tc_cipher_hidden,         :pointer,
           :tc_prf_hash_hidden,       :pointer,
           :tc_size_hidden_in_bytes,  :size_t,
           :tc_no_secure_erase,       :int,
           :tc_use_weak_keys,         :int
  end

  class TCApiVolinfo < FFI::Struct
    layout :tc_cipher,                [:char, 256],
           :tc_prf,                   [:char, 64 ],
           :tc_key_bits,              :int,
           :tc_size,                  :size_t,
           :tc_iv_offset,             :off_t,
           :tc_block_offset,          :off_t
  end

  attach_function :tc_api_init, [ :int ], :int
  attach_function :tc_api_uninit, [ ], :int
  attach_function :tc_api_info_volume, [ TCApiOpts.by_ref, TCApiVolinfo.by_ref ], :int
  attach_function :tc_api_create_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_map_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_unmap_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_check_cipher, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_check_prf_hash, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_get_error_msg, [ ], :string
end


