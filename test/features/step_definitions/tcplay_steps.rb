require 'rspec/expectations'
require 'expect'


Given /^I corrupt sectors ([^\s]+) to ([^\s]+) of volume ([^\s]+)$/ do |first,last,vol|
  loop_dev = @losetup.get_device("volumes/#{vol}")
  first = first.to_i
  last = last.to_i
  count = last-first+1

  IO.popen("dd if=/dev/urandom of=\"#{loop_dev}\" bs=512 count=#{count} seek=#{first} status=noxfer") { |io| Process.wait(io.pid) }
end


Given /^I corrupt sector ([^\s]+) of volume ([^\s]+)$/ do |first,vol|
  loop_dev = @losetup.get_device("volumes/#{vol}")
  first = first.to_i

  IO.popen("dd if=/dev/urandom of=\"#{loop_dev}\" bs=512 count=1 seek=#{first} status=noxfer") { |io| Process.wait(io.pid) }
end


Given /^I map volume ([^\s]+) as ([^\s]+) using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "-m #{map}",
    "-d #{loop_dev}"
  ]
  @args << "--pim=#{Integer(s['pim'], 10)}" if s['pim']
  @args << "--pim-hidden=#{Integer(s['pim_hidden'], 10)}" if s['pim_hidden']

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| @args << "-f \"keyfiles/#{kf}\"" } unless s['keyfiles_hidden'].nil?

  if ParseHelper.is_yes(s['protect_hidden'])
    @args << "-e"
    protect_hidden = true
  end

  @args << "--use-backup" if ParseHelper.is_yes(s['use_backup'])
  @args << "--use-hdr-file=#{s['header_file']}" unless s['header_file'].nil?

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end
    if protect_hidden == true
      tcplay_io.expect /Passphrase for hidden volume/, 60 do
        tcplay_io.write("#{s['passphrase_hidden']}\n")
      end
    end
    tcplay_io.close_write
    tcplay_io.read # Keep stdout open for tcplay's final status message.
  end

  @error = ($? != 0)

  @mappings << map unless @error
  @maps = DMSetupHelper.get_crypt_mappings("#{map}")
end


Given /^I create a volume ([^\s]+) of size (\d+)M with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  IO.popen("dd if=/dev/zero of=\"volumes/#{vol}\" bs=1M count=#{size_mb.to_i} status=noxfer") { |io| Process.wait(io.pid) }
  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "-c",
    "-d #{loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| @args << "-f \"keyfiles/#{kf}\"" } unless s['keyfiles_hidden'].nil?

  if ParseHelper.is_yes(s['create_hidden'])
    @args << "-g"
    create_hidden = true
  end

  @args << "--pim=#{Integer(s['pim'], 10)}" if s['pim']
  @args << "--pim-hidden=#{Integer(s['pim_hidden'], 10)}" if s['pim_hidden']
  @args << "-a #{s['pbkdf_prf'].strip}" unless s['pbkdf_prf'].nil?
  @args << "-b #{s['cipher'].strip}" unless s['cipher'].nil?
  @args << "-x #{s['pbkdf_prf_hidden'].strip}" unless s['pbkdf_prf_hidden'].nil?
  @args << "-y #{s['cipher_hidden'].strip}" unless s['cipher_hidden'].nil?
  
  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @files_to_delete << "volumes/#{vol}"

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    next unless tcplay_io.expect(/Passphrase/, 10)
    tcplay_io.write("#{s['passphrase']}\n")

    tcplay_io.expect /Repeat/, 10 do
      tcplay_io.write("#{s['passphrase']}\n")
    end

    if create_hidden == true
      tcplay_io.expect /Passphrase for hidden volume/, 10 do
        tcplay_io.write("#{s['passphrase_hidden']}\n")
      end

      tcplay_io.expect /Repeat/, 10 do
        tcplay_io.write("#{s['passphrase_hidden']}\n")
      end

      tcplay_io.expect /Size of hidden volume/, 10 do
        tcplay_io.write("#{s['hidden_mb']}M\n")
      end
    end
    tcplay_io.expect /Are you sure/, 10 do
      tcplay_io.write("y\n")
    end
    tcplay_io.close_write
    tcplay_io.read
  end
  @error = ($? != 0)
end



Given /^I request information about volume ([^\s]+) using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "-i",
    "-d #{loop_dev}"
  ]
  @args << "--pim=#{Integer(s['pim'], 10)}" if s['pim']
  @args << "--pim-hidden=#{Integer(s['pim_hidden'], 10)}" if s['pim_hidden']

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| @args << "-f \"keyfiles/#{kf}\"" } unless s['keyfiles_hidden'].nil?

  if ParseHelper.is_yes(s['protect_hidden'])
    @args << "-e"
    protect_hidden = true
  end

  @args << "--use-backup" if ParseHelper.is_yes(s['use_backup'])
  @args << "--use-hdr-file=#{s['header_file']}" unless s['header_file'].nil?

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @info = {}

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase:/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end
    if protect_hidden == true
      tcplay_io.expect /Passphrase for hidden volume:/, 60 do
        tcplay_io.write("#{s['passphrase_hidden']}\n")
      end
    end
    tcplay_io.each do |line|
      line.match(/^(.*):\s+(.*)$/) do |m|
        c = m.captures
        @info[c[0].downcase.strip] = c[1].downcase
      end
    end
  end
  @error = ($? != 0)
end


Given /^I request information about mapped volume ([^\s]+)$/ do |map|
  @args = [
    "-j #{map}"
  ]

  @info = {}

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.each do |line|
      line.match(/^(.*):\s+(.*)$/) do |m|
        c = m.captures
        @info[c[0].downcase.strip] = c[1].downcase
      end
    end
  end
  @error = ($? != 0)
end


Given /^I modify volume ([^\s]+) using the following settings:$/ do |vol,settings|
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "--modify",
    "-d #{loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  @args << "--pim=#{Integer(s['pim'], 10)}" if s['pim']
  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['new_keyfiles']) { |kf| @args << "--new-keyfile=\"keyfiles/#{kf}\"" } unless s['new_keyfiles'].nil?

  @args << "--new-pbkdf-prf=#{s['new_pbkdf_prf'].strip}" unless s['new_pbkdf_prf'].nil?
  @args << "--use-backup" if ParseHelper.is_yes(s['use_backup'])

  s['passphrase'] ||= ''
  s['new_passphrase'] ||= ''

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase:/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end

    tcplay_io.expect /New passphrase/, 60 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end

    tcplay_io.expect /Repeat/, 10 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end
    tcplay_io.close_write
    tcplay_io.read
  end
  @error = ($? != 0)
end


Given /^I modify volume ([^\s]+) by restoring from the backup header using the following settings:$/ do |vol,settings|
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "--modify",
    "--restore-from-backup-hdr",
    "-d #{loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  @args << "--pim=#{Integer(s['pim'], 10)}" if s['pim']
  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?

  s['passphrase'] ||= ''

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase:/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end
    tcplay_io.close_write
    tcplay_io.read
  end
  @error = ($? != 0)
end


Given(/^I modify volume ([^\s]+) by saving a header copy to ([^\s]+) using the following settings:$/) do |vol, hdr_file, settings|
  s = settings.rows_hash
  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "--modify",
    "--save-hdr-backup=#{hdr_file}",
    "-d #{loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?

  s['passphrase'] ||= ''
  s['new_passphrase'] ||= s['passphrase']

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase:/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end

    tcplay_io.expect /New passphrase/, 60 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end

    tcplay_io.expect /Repeat/, 10 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end
  end
  @error = ($? != 0)
end


Given(/^I modify volume ([^\s]+) by restoring from header copy ([^\s]+) using the following settings:$/) do |vol, hdr_file, settings|
  s = settings.rows_hash
  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "--no-retries",
    "--modify",
    "--use-hdr-file=#{hdr_file}",
    "-d #{loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?

  s['passphrase'] ||= ''
  s['new_passphrase'] ||= s['passphrase']

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    unless ParseHelper.is_yes(s['prompt_skipped'])
      tcplay_io.expect /Passphrase:/, 60 do
        tcplay_io.write("#{s['passphrase']}\n")
      end
    end

    tcplay_io.expect /New passphrase/, 60 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end

    tcplay_io.expect /Repeat/, 10 do
      tcplay_io.write("#{s['new_passphrase']}\n")
    end
  end
  @error = ($? != 0)
end


Then /^I expect dmsetup to have the following tables:$/ do |tables|
  tables.map_headers! { |h| h.to_sym }
  tables.diff!(@maps)
end

Then /^I expect no mapping named (\S+)$/ do |map|
  File.exist?("/dev/mapper/#{map}").should == false
end


Then /^I expect tcplay to report the following:$/ do |expected_info|
  expected_info.rows_hash.each_pair do |k,v|
    @info[k.downcase.strip].should == v.downcase
  end
end

Then %r{^I expect valid checksums in both AES-256-XTS/SHA512-VC headers of volume (\S+) with passphrase "([^"]*)"$} do |vol, passphrase|
  require 'openssl'
  require 'zlib'

  File.open("volumes/#{vol}", 'rb') do |volume|
    offsets = { 'primary' => 0, 'backup' => volume.size - 128 * 1024 }
    offsets.each do |name, offset|
      volume.seek(offset)
      salt = volume.read(64)
      cipher = OpenSSL::Cipher.new('aes-256-xts')
      cipher.decrypt
      cipher.key = OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, 500_000, cipher.key_len, 'SHA512')
      cipher.iv = "\0" * cipher.iv_len
      header = cipher.update(volume.read(448)) + cipher.final

      stored_crc = header.byteslice(188, 4).unpack1('N')
      expected_crc = Zlib.crc32(header.byteslice(0, 188))
      stored_crc.should eq(expected_crc), "Incorrect CRC32 in the #{name} volume header"
    end
  end
end

Then /^I expect tcplay to succeed$/ do
  @error.should == false
end

Then /^I expect tcplay to fail$/ do
  @error.should == true
end

Then /^I expect to see the following ciphers:$/ do |ciphers|
  ciphers.map_headers! { |h| h.to_sym }
  @ciphers.should match_array(ciphers.hashes)
end

Then /^I expect to see the following PRFs:$/ do |prfs|
  prfs = prfs.raw.map { |x| x.first.downcase }
  @prfs.should match_array(prfs)
end


Before do
  @tcplay = "#{ENV['BUILD_PATH'] || ".."}/tcplay"
  @maps = []
  @mappings = []
  @info = {}
  @files_to_delete = []
  @losetup = LOSetupHelper.new
end


After('@cmdline') do
  @mappings.each { |m| IO.popen("#{@tcplay} -u #{m}") { |io| Process.wait(io.pid) } }
  @losetup.detach_all

  @files_to_delete.each { |f| File.unlink(f) }
end

