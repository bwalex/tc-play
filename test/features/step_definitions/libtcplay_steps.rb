require 'rspec/expectations'
require 'expect'


Given /^I map volume ([^\s]+) as ([^\s]+) with the API using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("map")

  r = TCplayLib.tc_api_task_set(task, "map_name", :string, map)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  unless s['keyfiles_hidden'].nil?
    ParseHelper.csv_parse(s['keyfiles_hidden']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "h_keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  if ParseHelper.is_yes(s['protect_hidden'])
    r = TCplayLib.tc_api_task_set(task, "protect_hidden", :int, 1)
    r.should == TCplayLib::TC_OK
    protect_hidden = true
  end

  if not s['header_file'].nil?
    r = TCplayLib.tc_api_task_set(task, "header_from_file", :string, s['header_file'])
    r.should == TCplayLib::TC_OK
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "h_passphrase", :string, s['passphrase_hidden'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "use_backup_header", :int,
    (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup'])))
  r.should == TCplayLib::TC_OK

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
    #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)

  @mappings << map unless @error
  @maps = DMSetupHelper.get_crypt_mappings("#{map}")
end


Given /^I create a volume ([^\s]+) of size (\d+)M using the API with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  IO.popen("dd if=/dev/zero of=\"volumes/#{vol}\" bs=1M count=#{size_mb.to_i} status=noxfer") { |io| Process.wait(io.pid) }
  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("create")

  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  unless s['keyfiles_hidden'].nil?
    ParseHelper.csv_parse(s['keyfiles_hidden']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "h_keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  if ParseHelper.is_yes(s['create_hidden'])
    r = TCplayLib.tc_api_task_set(task, "hidden_size_bytes", :int64,
                                  1024*1024*s['hidden_mb'].to_i)
    r.should == TCplayLib::TC_OK
    create_hidden = true
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "h_passphrase", :string, s['passphrase_hidden'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "weak_keys_and_salt", :int, 1)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "secure_erase", :int, 0)
  r.should == TCplayLib::TC_OK

  r = TCplayLib.tc_api_task_set(task, "prf_algo", :string, s['pbkdf_prf'].strip) unless s['pbkdf_prf'].nil?
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "h_prf_algo", :string, s['pbkdf_prf_hidden'].strip) unless s['pbkdf_prf_hidden'].nil?
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "cipher_chain", :string, s['cipher'].strip) unless s['cipher'].nil?
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "h_cipher_chain", :string, s['cipher_hidden'].strip) unless s['cipher_hidden'].nil?
  r.should == TCplayLib::TC_OK

  @files_to_delete << "volumes/#{vol}"

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
    #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)
end



Given /^I request information about volume ([^\s]+) with the API using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("info")
  task.read_pointer().null?.should == false

  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  unless s['keyfiles_hidden'].nil?
    ParseHelper.csv_parse(s['keyfiles_hidden']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "h_keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  if ParseHelper.is_yes(s['protect_hidden'])
    r = TCplayLib.tc_api_task_set(task, "protect_hidden", :int, 1)
    r.should == TCplayLib::TC_OK
    protect_hidden = true
  end

  if not s['header_file'].nil?
    r = TCplayLib.tc_api_task_set(task, "header_from_file", :string, s['header_file'])
    r.should == TCplayLib::TC_OK
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "h_passphrase", :string, s['passphrase_hidden'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "use_backup_header", :int,
    (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup'])))
  r.should == TCplayLib::TC_OK

  @info = {}

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
    #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  unless @error
    buf = FFI::MemoryPointer.new(1024)
    r = TCplayLib.tc_api_task_info_get(task, "device", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['device'] = buf.read_string

    r = TCplayLib.tc_api_task_info_get(task, "prf", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['pbkdf2 prf'] = buf.read_string.downcase

    r = TCplayLib.tc_api_task_info_get(task, "cipher", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['cipher'] = buf.read_string.downcase

    buf = FFI::MemoryPointer.new :int

    r = TCplayLib.tc_api_task_info_get(task, "key_bits", :size_t, 4, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['key length'] = "#{buf.get_int(0)} bits"

    buf = FFI::MemoryPointer.new :int64

    r = TCplayLib.tc_api_task_info_get(task, "size", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['volume size'] = "#{buf.get_int64(0)} bytes"

    r = TCplayLib.tc_api_task_info_get(task, "iv_offset", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['iv offset'] = "#{buf.get_int64(0)} bytes"

    r = TCplayLib.tc_api_task_info_get(task, "block_offset", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['block offset'] = "#{buf.get_int64(0)} bytes"
  end

  TCplayLib.tc_api_task_uninit(task)
end


Given /^I request information about mapped volume ([^\s]+) with the API$/ do |map|
  task = TCplayLib.tc_api_task_init("info_mapped")
  task.read_pointer().null?.should == false

  r = TCplayLib.tc_api_task_set(task, "map_name", :string, map)
  r.should == TCplayLib::TC_OK

  @info = {}

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
    #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  unless @error
    buf = FFI::MemoryPointer.new(1024)
    r = TCplayLib.tc_api_task_info_get(task, "device", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['device'] = buf.read_string

    r = TCplayLib.tc_api_task_info_get(task, "prf", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['pbkdf2 prf'] = buf.read_string.downcase

    r = TCplayLib.tc_api_task_info_get(task, "cipher", :size_t, 1024, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['cipher'] = buf.read_string.downcase

    buf = FFI::MemoryPointer.new :int

    r = TCplayLib.tc_api_task_info_get(task, "key_bits", :size_t, 4, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['key length'] = "#{buf.get_int(0)} bits"

    buf = FFI::MemoryPointer.new :int64

    r = TCplayLib.tc_api_task_info_get(task, "size", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['volume size'] = "#{buf.get_int64(0)} bytes"

    r = TCplayLib.tc_api_task_info_get(task, "iv_offset", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['iv offset'] = "#{buf.get_int64(0)} bytes"

    r = TCplayLib.tc_api_task_info_get(task, "block_offset", :size_t, 8, :pointer, buf)
    r.should == TCplayLib::TC_OK
    @info['block offset'] = "#{buf.get_int64(0)} bytes"
  end

  TCplayLib.tc_api_task_uninit(task)
end


Given /^I modify volume ([^\s]+) with the API using the following settings:$/ do |vol,settings|
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("modify")

  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  unless s['new_keyfiles'].nil?
    ParseHelper.csv_parse(s['new_keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "new_keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  if not s['header_file'].nil?
    r = TCplayLib.tc_api_task_set(task, "header_from_file", :string, s['header_file'])
    r.should == TCplayLib::TC_OK
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "new_passphrase", :string, s['new_passphrase'] || '')
  r.should == TCplayLib::TC_OK

  unless s['new_pbkdf_prf'].nil?
    r = TCplayLib.tc_api_task_set(task, "new_prf_algo", :string, s['new_pbkdf_prf'].strip)
    r.should == TCplayLib::TC_OK
  end

  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "weak_keys_and_salt", :int, 1)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "use_backup_header", :int,
    (s['use_backup'].nil? ? 0 : ParseHelper.is_yes(s['use_backup'])))
  r.should == TCplayLib::TC_OK

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
  #  #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)
end

Given /^I modify volume ([^\s]+) with the API by restoring from the backup header using the following settings:$/ do |vol,settings|
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("restore")
  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK

  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "weak_keys_and_salt", :int, 1)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "use_backup_header", :int, 1)
  r.should == TCplayLib::TC_OK

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
  #  #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)
end


Given(/^I modify volume ([^\s]+) with the API by saving a header copy to ([^\s]+) using the following settings:$/) do |vol, hdr_file, settings|
  s = settings.rows_hash
  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("modify")

  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  s['new_passphrase'] ||= s['passphrase']
  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "new_passphrase", :string, s['new_passphrase'])
  r.should == TCplayLib::TC_OK

  r = TCplayLib.tc_api_task_set(task, "save_header_to_file", :string, hdr_file)
  r.should == TCplayLib::TC_OK

  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "weak_keys_and_salt", :int, 1)
  r.should == TCplayLib::TC_OK

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
  #  #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)
end


Given(/^I modify volume ([^\s]+) with the API by restoring from header copy ([^\s]+) using the following settings:$/) do |vol, hdr_file, settings|
  s = settings.rows_hash
  loop_dev = @losetup.get_device("volumes/#{vol}")

  task = TCplayLib.tc_api_task_init("restore")
  r = TCplayLib.tc_api_task_set(task, "dev", :string, loop_dev)
  r.should == TCplayLib::TC_OK

  unless s['keyfiles'].nil?
    ParseHelper.csv_parse(s['keyfiles']) do |kf|
      r = TCplayLib.tc_api_task_set(task, "keyfiles", :string, "keyfiles/#{kf}")
      r.should == TCplayLib::TC_OK
    end
  end

  r = TCplayLib.tc_api_task_set(task, "passphrase", :string, s['passphrase'] || '')
  r.should == TCplayLib::TC_OK

  r = TCplayLib.tc_api_task_set(task, "interactive", :int, 0)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "weak_keys_and_salt", :int, 1)
  r.should == TCplayLib::TC_OK
  r = TCplayLib.tc_api_task_set(task, "header_from_file", :string, hdr_file)
  r.should == TCplayLib::TC_OK

  @error = (TCplayLib.tc_api_task_do(task) != TCplayLib::TC_OK)
  if (@error)
  #  #@err_str = TCplayLib.tc_api_get_error_msg()
  end

  TCplayLib.tc_api_task_uninit(task)
end


Given /^I query the available PRFs with the API$/ do
  @prfs = []

  callback = Proc.new do |unused, name|
    @prfs << name.downcase
    0
  end

  r = TCplayLib.tc_api_prf_iterate(callback, nil)
  r.should == TCplayLib::TC_OK
end


Given /^I query the available ciphers with the API$/ do
  @ciphers = []

  callback = Proc.new do |unused, name, klen, length|
    @ciphers << {
      :name   => name.upcase,
      :klen   => "#{klen}",
      :length => "#{length}"
    }
    0
  end

  r = TCplayLib.tc_api_cipher_iterate(callback, nil)
  r.should == TCplayLib::TC_OK
end



Before('@api') do
  r = TCplayLib.tc_api_init(1)
  r.should == TCplayLib::TC_OK
end


After('@api') do
  @mappings.each do |m|
    task = TCplayLib.tc_api_task_init("unmap")
    TCplayLib.tc_api_task_set(task,
                              "map_name",
                              :string, "#{m}")
    r = TCplayLib.tc_api_task_do(task)
    r.should == TCplayLib::TC_OK
    TCplayLib.tc_api_task_uninit(task)
  end

  @losetup.detach_all

  r = TCplayLib.tc_api_uninit()
  r.should == TCplayLib::TC_OK

  @files_to_delete.each { |f| File.unlink(f) }
end
