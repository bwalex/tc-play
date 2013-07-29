require 'rspec/expectations'
require 'expect'


Given /^I map volume ([^\s]+) as ([^\s]+) with the API using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_map_name] = FFI::MemoryPointer.from_string(map)
  opts[:tc_device] = FFI::MemoryPointer.from_string(loop_dev)

  unless s['keyfiles'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles] = FFIHelper.str_array_to_p(keyfiles)
  end

  unless s['keyfiles_hidden'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles_hidden] = FFIHelper.str_array_to_p(keyfiles)
  end

  if ParseHelper.is_yes(s['protect_hidden'])
    opts[:tc_protect_hidden] = 1
    protect_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0
  opts[:tc_use_backup] = (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup']))

  @error = (TCplayLib.tc_api_map_volume(opts) == TCplayLib::TC_ERR)
  if (@error)
    @err_str = TCplayLib.tc_api_get_error_msg()
  end

  @mappings << map unless @error
  @maps = DMSetupHelper.get_crypt_mappings("#{map}")
end


Given /^I create a volume ([^\s]+) of size (\d+)M using the API with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  IO.popen("dd if=/dev/zero of=\"volumes/#{vol}\" bs=1M count=#{size_mb.to_i} status=none") { |io| Process.wait(io.pid) }
  loop_dev = @losetup.get_device("volumes/#{vol}")

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_device] = FFI::MemoryPointer.from_string(loop_dev)

  unless s['keyfiles'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles] = FFIHelper.str_array_to_p(keyfiles)
  end

  unless s['keyfiles_hidden'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles_hidden] = FFIHelper.str_array_to_p(keyfiles)
  end

  if ParseHelper.is_yes(s['create_hidden'])
    opts[:tc_size_hidden_in_bytes] = 1024*1024*s['hidden_mb'].to_i
    create_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0
  opts[:tc_no_secure_erase] = 1
  opts[:tc_use_weak_keys] = 1

  opts[:tc_prf_hash] = FFI::MemoryPointer.from_string(s['pbkdf_prf'].strip) unless s['pbkdf_prf'].nil?
  opts[:tc_cipher] = FFI::MemoryPointer.from_string(s['cipher'].strip) unless s['cipher'].nil?
  opts[:tc_prf_hash_hidden] = FFI::MemoryPointer.from_string(s['pbkdf_prf_hidden'].strip) unless s['pbkdf_prf_hidden'].nil?
  opts[:tc_cipher_hidden] = FFI::MemoryPointer.from_string(s['cipher_hidden'].strip) unless s['cipher_hidden'].nil?
  
  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @files_to_delete << "volumes/#{vol}"

  @error = (TCplayLib.tc_api_create_volume(opts) == TCplayLib::TC_ERR)
  if (@error)
    @err_str = TCplayLib.tc_api_get_error_msg()
  end
end



Given /^I request information about volume ([^\s]+) with the API using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_device] = FFI::MemoryPointer.from_string(loop_dev)

  unless s['keyfiles'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles] = FFIHelper.str_array_to_p(keyfiles)
  end

  unless s['keyfiles_hidden'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles_hidden] = FFIHelper.str_array_to_p(keyfiles)
  end

  if ParseHelper.is_yes(s['protect_hidden'])
    opts[:tc_protect_hidden] = 1
    protect_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0
  opts[:tc_use_backup] = (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup']))

  @info = {}

  api_info = TCplayLib::TCApiVolinfo.new

  @error = (TCplayLib.tc_api_info_volume(opts, api_info) == TCplayLib::TC_ERR)
  if (@error)
    @err_str = TCplayLib.tc_api_get_error_msg()
  end

  @info['device'] = api_info[:tc_device].to_ptr.get_string(0)
  @info['pbkdf2 prf'] = api_info[:tc_prf].to_ptr.get_string(0).downcase
  @info['cipher'] = api_info[:tc_cipher].to_ptr.get_string(0).downcase
  @info['key length'] = "#{api_info[:tc_key_bits].to_i} bits"
  @info['volume size'] = "#{api_info[:tc_size]} bytes"
  @info['iv offset'] =  "#{api_info[:tc_iv_offset]} bytes"
  @info['block offset'] = "#{api_info[:tc_block_offset]} bytes"
end


Given /^I request information about mapped volume ([^\s]+) with the API$/ do |map|
  opts = TCplayLib::TCApiOpts.new

  opts[:tc_map_name] = FFI::MemoryPointer.from_string(map)

  @info = {}

  api_info = TCplayLib::TCApiVolinfo.new

  @error = (TCplayLib.tc_api_info_mapped_volume(opts, api_info) == TCplayLib::TC_ERR)
  if (@error)
    @err_str = TCplayLib.tc_api_get_error_msg()
  end

  @info['device'] = api_info[:tc_device].to_ptr.get_string(0)
  @info['pbkdf2 prf'] = api_info[:tc_prf].to_ptr.get_string(0).downcase
  @info['cipher'] = api_info[:tc_cipher].to_ptr.get_string(0).downcase
  @info['key length'] = "#{api_info[:tc_key_bits].to_i} bits"
  @info['volume size'] = "#{api_info[:tc_size]} bytes"
  @info['iv offset'] =  "#{api_info[:tc_iv_offset]} bytes"
  @info['block offset'] = "#{api_info[:tc_block_offset]} bytes"
end


Given /^I modify volume ([^\s]+) with the API using the following settings:$/ do |vol,settings|
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_device] = FFI::MemoryPointer.from_string(loop_dev)

  unless s['keyfiles'].nil?
    keyfiles = ParseHelper.csv_parse(s['keyfiles']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_keyfiles] = FFIHelper.str_array_to_p(keyfiles)
  end

  unless s['new_keyfiles'].nil?
    new_keyfiles = ParseHelper.csv_parse(s['new_keyfiles']) { |kf| "keyfiles/#{kf}" }
    opts[:tc_new_keyfiles] = FFIHelper.str_array_to_p(new_keyfiles)
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_new_passphrase] = FFI::MemoryPointer.from_string(s['new_passphrase'] || '')
  opts[:tc_new_prf_hash] = FFI::MemoryPointer.from_string(s['new_pbkdf_prf'].strip) unless s['new_pbkdf_prf'].nil?
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0
  opts[:tc_use_weak_salt] = 1
  opts[:tc_use_backup] = (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup']))

  @error = (TCplayLib.tc_api_modify_volume(opts) == TCplayLib::TC_ERR)
  if (@error)
    @err_str = TCplayLib.tc_api_get_error_msg()
  end
end


Before('@api') do
  r = TCplayLib.tc_api_init(1)
  r.should == TCplayLib::TC_OK
end


After('@api') do
  opts = TCplayLib::TCApiOpts.new

  @mappings.each do |m|
    opts[:tc_map_name] = FFI::MemoryPointer.from_string("#{m}")
    r = TCplayLib.tc_api_unmap_volume(opts)
    r.should == TCplayLib::TC_OK
  end

  @losetup.detach_all

  r = TCplayLib.tc_api_uninit()
  r.should == TCplayLib::TC_OK

  @files_to_delete.each { |f| File.unlink(f) }
end
