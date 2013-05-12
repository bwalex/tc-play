require 'rspec/expectations'
require 'expect'


Given /^I map volume ([^\s]+) as ([^\s]+) with the API using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_map_name] = FFI::MemoryPointer.from_string(map)
  opts[:tc_device] = FFI::MemoryPointer.from_string(@loop_dev)

  if not s['keyfiles'].nil?
    keyfiles = []
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| keyfiles << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles << nil
    opts[:tc_keyfiles] = FFI::MemoryPointer.new(:pointer, keyfiles.length)
    keyfiles.each_with_index { |p,i| opts[:tc_keyfiles][i].put_pointer(0, p) }
  end

  if not s['keyfiles_hidden'].nil?
    keyfiles_hidden = []
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| keyfiles_hidden << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles_hidden << nil
    opts[:tc_keyfiles_hidden] = FFI::MemoryPointer.new(:pointer, keyfiles_hidden.length)
    keyfiles_hidden.each_with_index { |p,i| opts[:tc_keyfiles_hidden][i].put_pointer(0, p) }
  end

  if (not s['protect_hidden'].nil?) and s['protect_hidden'].casecmp("yes")
    opts[:tc_protect_hidden] = 1
    protect_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0

  @clean_loopdev = true

  IO.popen("losetup #{@loop_dev} volumes/#{vol}") { |io| Process.wait(io.pid) }

  r = TCplayLib.tc_api_map_volume(opts)
  if (r == TCplayLib::TC_ERR)
    err_str = TCplayLib.tc_api_get_error_msg()
    puts "Error from tc_api_map_volume: #{err_str}"
  end
  r.should == TCplayLib::TC_OK

  @maps = []
  IO.popen("dmsetup table --showkeys") do |dmsetup_io|
    dmsetup_io.each do |line|
      line.match(/^(#{map}.*):\s+(\d+)\s+(\d+)\s+crypt\s+([^\s]+)\s+([a-fA-F0-9]+)\s+(\d+)\s+[^\s]+\s+(\d+)/) do |m|
        c = m.captures
        map = {
          :name       => c[0],
          :begin      => c[1],
          :end        => c[2],
          :algo       => c[3],
          :key        => c[4],
          :offset     => c[5],
          :iv_offset  => c[6]
        }
        @maps << map
      end
    end
  end
end


Given /^I create a volume ([^\s]+) of size (\d+)M using the API with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_device] = FFI::MemoryPointer.from_string(@loop_dev)

  if not s['keyfiles'].nil?
    keyfiles = []
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| keyfiles << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles << nil
    opts[:tc_keyfiles] = FFI::MemoryPointer.new(:pointer, keyfiles.length)
    keyfiles.each_with_index { |p,i| opts[:tc_keyfiles][i].put_pointer(0, p) }
  end

  if not s['keyfiles_hidden'].nil?
    keyfiles_hidden = []
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| keyfiles_hidden << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles_hidden << nil
    opts[:tc_keyfiles_hidden] = FFI::MemoryPointer.new(:pointer, keyfiles_hidden.length)
    keyfiles_hidden.each_with_index { |p,i| opts[:tc_keyfiles_hidden][i].put_pointer(0, p) }
  end

  if (not s['create_hidden'].nil?) and s['create_hidden'].casecmp("yes")
    opts[:tc_size_hidden_in_bytes] = 1024*1024*s['hidden_mb'].to_i
    create_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0
  opts[:tc_no_secure_erase] = 1
  opts[:tc_use_weak_keys] = 1

  if not s['pbkdf_prf'].nil?
    opts[:tc_prf_hash] = FFI::MemoryPointer.from_string(s['pbkdf_prf'].strip)
  end

  if not s['cipher'].nil?
    opts[:tc_cipher] = FFI::MemoryPointer.from_string(s['cipher'].strip)
  end
  
  if not s['pbkdf_prf_hidden'].nil?
    opts[:tc_prf_hash_hidden] = FFI::MemoryPointer.from_string(s['pbkdf_prf_hidden'].strip)
  end
  
  if not s['cipher_hidden'].nil?
    opts[:tc_cipher_hidden] = FFI::MemoryPointer.from_string(s['cipher_hidden'].strip)
  end
  
  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @files_to_delete << "volumes/#{vol}"

  IO.popen("dd if=/dev/zero of=\"volumes/#{vol}\" bs=1M count=#{size_mb.to_i}") { |io| Process.wait(io.pid) }
  IO.popen("losetup #{@loop_dev} volumes/#{vol}") { |io| Process.wait(io.pid) }

  r = TCplayLib.tc_api_create_volume(opts)
  if (r == TCplayLib::TC_ERR)
    err_str = TCplayLib.tc_api_get_error_msg()
    puts "Error from tc_api_create_volume: #{err_str}"
  end
  r.should == TCplayLib::TC_OK

  IO.popen("losetup -d #{@loop_dev}") { |io| Process.wait(io.pid) }
end



Given /^I request information about volume ([^\s]+) with the API using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  opts = TCplayLib::TCApiOpts.new

  opts[:tc_device] = FFI::MemoryPointer.from_string(@loop_dev)

  if not s['keyfiles'].nil?
    keyfiles = []
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| keyfiles << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles << nil
    opts[:tc_keyfiles] = FFI::MemoryPointer.new(:pointer, keyfiles.length)
    keyfiles.each_with_index { |p,i| opts[:tc_keyfiles][i].put_pointer(0, p) }
  end

  if not s['keyfiles_hidden'].nil?
    keyfiles_hidden = []
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| keyfiles_hidden << FFI::MemoryPointer.from_string(kf.strip) }
    keyfiles_hidden << nil
    opts[:tc_keyfiles_hidden] = FFI::MemoryPointer.new(:pointer, keyfiles_hidden.length)
    keyfiles_hidden.each_with_index { |p,i| opts[:tc_keyfiles_hidden][i].put_pointer(0, p) }
  end

  if (not s['protect_hidden'].nil?) and s['protect_hidden'].casecmp("yes")
    opts[:tc_protect_hidden] = 1
    protect_hidden = true
  end

  opts[:tc_passphrase] = FFI::MemoryPointer.from_string(s['passphrase'] || '')
  opts[:tc_passphrase_hidden] = FFI::MemoryPointer.from_string(s['passphrase_hidden'] || '')
  opts[:tc_interactive_prompt] = 0
  opts[:tc_use_system_encryption] = 0

  @info = {}

  @clean_loopdev = false
  IO.popen("losetup #{@loop_dev} volumes/#{vol}") { |io| Process.wait(io.pid) }

  api_info = TCplayLib::TCApiVolinfo.new

  r = TCplayLib.tc_api_info_volume(opts, api_info)
  if (r == TCplayLib::TC_ERR)
    err_str = TCplayLib.tc_api_get_error_msg()
    puts "Error from tc_api_map_volume: #{err_str}"
  end
  r.should == TCplayLib::TC_OK

  @info['pbkdf2 prf'] = api_info[:tc_prf].to_ptr.get_string(0).downcase
  @info['cipher'] = api_info[:tc_cipher].to_ptr.get_string(0).downcase
  @info['key length'] = "#{api_info[:tc_key_bits].to_i} bits"
  @info['volume size'] = "#{api_info[:tc_size]} bytes"
  @info['iv offset'] =  "#{api_info[:tc_iv_offset]} bytes"
  @info['block offset'] = "#{api_info[:tc_block_offset]} bytes"
  
  IO.popen("losetup -d #{@loop_dev}") { |io| Process.wait(io.pid) }
end


Before('@api') do
  r = TCplayLib.tc_api_init(1)
  r.should == TCplayLib::TC_OK
end


After('@api') do
  opts = TCplayLib::TCApiOpts.new

  unless @maps.empty?
    opts[:tc_map_name] = FFI::MemoryPointer.from_string("tcplay_test")
    r = TCplayLib.tc_api_unmap_volume(opts)
    r.should == TCplayLib::TC_OK
  end

  IO.popen("losetup -d #{@loop_dev}") { |io| Process.wait(io.pid) } if @clean_loopdev
  
  r = TCplayLib.tc_api_uninit()
  r.should == TCplayLib::TC_OK

  @files_to_delete.each { |f| File.unlink(f) }
end

