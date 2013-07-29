require 'ffi'

module TCplayLib
  extend FFI::Library

  ffi_lib [ "../libtcplay.so" ]

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

    # Fields for mapping / info / modify
           :tc_password_retries,      :int,
           :tc_interactive_prompt,    :int,
           :tc_prompt_timeout,        :ulong,
           :tc_use_system_encryption, :int,
           :tc_system_device,         :pointer,
           :tc_use_fde,               :int,
           :tc_use_backup,            :int,

    # Fields for modify
           :tc_new_passphrase,        :pointer,
           :tc_new_keyfiles,          :pointer,
           :tc_new_prf_hash,          :pointer,
           :tc_use_weak_salt,         :int,

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
    layout :tc_device,                [:char, 1024],
           :tc_cipher,                [:char,  256],
           :tc_prf,                   [:char,   64],
           :tc_key_bits,              :int,
           :tc_size,                  :size_t,
           :tc_iv_offset,             :off_t,
           :tc_block_offset,          :off_t
  end

  attach_function :tc_api_init, [ :int ], :int
  attach_function :tc_api_uninit, [ ], :int
  attach_function :tc_api_info_volume, [ TCApiOpts.by_ref, TCApiVolinfo.by_ref ], :int
  attach_function :tc_api_info_mapped_volume, [ TCApiOpts.by_ref, TCApiVolinfo.by_ref ], :int
  attach_function :tc_api_create_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_map_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_unmap_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_modify_volume, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_check_cipher, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_check_prf_hash, [ TCApiOpts.by_ref ], :int
  attach_function :tc_api_get_error_msg, [ ], :string
end


module FFIHelper
  # String Array to null-terminated pointer array
  def self.str_array_to_p(a)
    pointers = []
    a.each { |v| pointers << FFI::MemoryPointer.from_string(v) }
    pointers << nil

    ptr = FFI::MemoryPointer.new(:pointer, pointers.length)
    pointers.each_with_index { |p,i| ptr[i].write_pointer(p) }
    return ptr
  end
end


module ParseHelper
  def self.csv_parse(field)
    a = []
    field.split(%r{\s*,\s*}).each do |str|
      v = str.strip
      v = yield v if block_given?
      a << v
    end
    return a
  end

  def self.is_yes(field)
    return false if field.nil?
    return true if field.casecmp("yes") or field.casecmp("y")
    return false
  end
end


module DMSetupHelper
  def self.get_crypt_mappings(name)
    maps = []
    IO.popen("dmsetup table --showkeys") do |dmsetup_io|
      dmsetup_io.each do |line|
        line.match(/^(#{name}.*):\s+(\d+)\s+(\d+)\s+crypt\s+([^\s]+)\s+([a-fA-F0-9]+)\s+(\d+)\s+[^\s]+\s+(\d+)/) do |m|
          c = m.captures
          mapping = {
            :name       => c[0],
            :begin      => c[1],
            :end        => c[2],
            :algo       => c[3],
            :key        => c[4],
            :offset     => c[5],
            :iv_offset  => c[6]
          }
          maps << mapping
        end
      end
      maps.sort! { |x,y| y[:name] <=> x[:name] }
    end

    return maps
  end
end

class LOSetupHelper
  def initialize
    @loopdevs = {}
  end

  def find_free
    free_dev = nil
    IO.popen("losetup -f") { |losetup_io| free_dev = losetup_io.read.chomp }
    return free_dev
  end

  def get_device(path)
    if @loopdevs[path].nil?
      @loopdevs[path] = find_free()
      IO.popen("losetup #{@loopdevs[path]} \"#{path}\"") { |io| Process.wait(io.pid) }
    end

    return @loopdevs[path]
  end

  def detach(path)
    unless @loopdevs[path].nil?
      IO.popen("losetup -d #{@loopdevs[path]}") { |io| Process.wait(io.pid) }
      @loopdevs.delete(path)
    end
  end

  def detach_all
    @loopdevs.each do |p,d|
      IO.popen("losetup -d #{d}") { |io| Process.wait(io.pid) }
      @loopdevs.delete(p)
    end
  end
end

