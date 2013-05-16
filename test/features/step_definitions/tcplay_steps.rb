require 'rspec/expectations'
require 'expect'


Given /^I map volume ([^\s]+) as ([^\s]+) using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "-m #{map}",
    "-d #{loop_dev}"
  ]

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| @args << "-f \"keyfiles/#{kf}\"" } unless s['keyfiles_hidden'].nil?

  if ParseHelper.is_yes(s['protect_hidden'])
    @args << "-e"
    protect_hidden = true
  end

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.expect /Passphrase/, 10 do
      tcplay_io.write("#{s['passphrase']}\n")
    end
    if protect_hidden == true
      tcplay_io.expect /Passphrase for hidden volume/, 10 do
        tcplay_io.write("#{s['passphrase_hidden']}\n")
      end
    end
  end

  @mappings << map
  @maps = DMSetupHelper.get_crypt_mappings("#{map}")
end


Given /^I create a volume ([^\s]+) of size (\d+)M with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  IO.popen("dd if=/dev/zero of=\"volumes/#{vol}\" bs=1M count=#{size_mb.to_i} status=none") { |io| Process.wait(io.pid) }
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

  @args << "-a #{s['pbkdf_prf'].strip}" unless s['pbkdf_prf'].nil?
  @args << "-b #{s['cipher'].strip}" unless s['cipher'].nil?
  @args << "-x #{s['pbkdf_prf_hidden'].strip}" unless s['pbkdf_prf_hidden'].nil?
  @args << "-y #{s['cipher_hidden'].strip}" unless s['cipher_hidden'].nil?
  
  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @files_to_delete << "volumes/#{vol}"

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.expect /Passphrase/, 10 do
      tcplay_io.write("#{s['passphrase']}\n")
    end

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
  end
end



Given /^I request information about volume ([^\s]+) using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  loop_dev = @losetup.get_device("volumes/#{vol}")
  @args = [
    "-i",
    "-d #{loop_dev}"
  ]

  ParseHelper.csv_parse(s['keyfiles']) { |kf| @args << "-k \"keyfiles/#{kf}\"" } unless s['keyfiles'].nil?
  ParseHelper.csv_parse(s['keyfiles_hidden']) { |kf| @args << "-f \"keyfiles/#{kf}\"" } unless s['keyfiles_hidden'].nil?

  if ParseHelper.is_yes(s['protect_hidden'])
    @args << "-e"
    protect_hidden = true
  end

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @info = {}

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.expect /Passphrase:/, 10 do
      tcplay_io.write("#{s['passphrase']}\n")
    end
    if protect_hidden == true
      tcplay_io.expect /Passphrase for hidden volume:/, 10 do
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
end


Then /^I expect dmsetup to have the following tables:$/ do |tables|
  tables.map_headers! { |h| h.to_sym }
  tables.diff!(@maps)
end


Then /^I expect tcplay to report the following:$/ do |expected_info|
  expected_info.rows_hash.each_pair do |k,v|
    @info[k.downcase.strip].should == v.downcase
  end
end


Before do
  @tcplay = "../tcplay"
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

