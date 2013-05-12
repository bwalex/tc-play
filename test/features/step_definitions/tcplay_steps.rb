require 'rspec/expectations'
require 'expect'


Given /^I map volume ([^\s]+) as ([^\s]+) using the following settings:$/ do |vol,map,settings|
  protect_hidden = false
  s = settings.rows_hash

  @args = [
    "-m #{map}",
    "-d #{@loop_dev}"
  ]

  if not s['keyfiles'].nil?
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| @args << "-k \"#{kf.strip}\"" }
  end

  if not s['keyfiles_hidden'].nil?
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| @args << "-f \"#{kf.strip}\"" }
  end

  if (not s['protect_hidden'].nil?) and s['protect_hidden'].casecmp("yes")
    @args << "-e"
    protect_hidden = true
  end

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @clean_loopdev = true

  IO.popen("losetup #{@loop_dev} #{vol}")
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


Given /^I create a volume ([^\s]+) of size (\d+)M with the following parameters:$/ do |vol,size_mb,params|
  create_hidden = false
  s = params.rows_hash

  @args = [
    "-c",
    "-d #{@loop_dev}",
    "-w", # We don't want to wait for /dev/random to have enough entropy
  ]

  if not s['keyfiles'].nil?
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| @args << "-k \"#{kf.strip}\"" }
  end

  if not s['keyfiles_hidden'].nil?
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| @args << "-f \"#{kf.strip}\"" }
  end

  if (not s['create_hidden'].nil?) and s['create_hidden'].casecmp("yes")
    @args << "-g"
    create_hidden = true
  end

  if not s['pbkdf_prf'].nil?
    @args << "-a #{s['pbkdf_prf'].strip}"
  end

  if not s['cipher'].nil?
    @args << "-b #{s['cipher'].strip}"
  end
  
  if not s['pbkdf_prf_hidden'].nil?
    @args << "-x #{s['pbkdf_prf_hidden'].strip}"
  end
  
  if not s['cipher_hidden'].nil?
    @args << "-y #{s['cipher_hidden'].strip}"
  end
  
  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  IO.popen("dd if=/dev/zero of=\"#{vol}\" bs=1M count=#{size_mb.to_i}")
  IO.popen("losetup #{@loop_dev} #{vol}")

  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.expect /Passphrase/, 10 do
      tcplay_io.write("#{s['passphrase']}\n")
    end
    if create_hidden == true
      tcplay_io.expect /Passphrase for hidden volume/, 10 do
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

  IO.popen("losetup -d #{@loop_dev}")
end



Given /^I request information about volume ([^\s]+) using the following settings:$/ do |vol,settings|
  protect_hidden = false
  s = settings.rows_hash

  @args = [
    "-i",
    "-d #{@loop_dev}"
  ]

  if not s['keyfiles'].nil?
    s['keyfiles'].split(%r{\s*,\s*}).each { |kf| @args << "-k \"#{kf.strip}\"" }
  end

  if not s['keyfiles_hidden'].nil?
    s['keyfiles_hidden'].split(%r{\s*,\s*}).each { |kf| @args << "-f \"#{kf.strip}\"" }
  end

  if (not s['protect_hidden'].nil?) and s['protect_hidden'].casecmp("yes")
    @args << "-e"
    protect_hidden = true
  end

  s['passphrase'] ||= ''
  s['passphrase_hidden'] ||= ''

  @info = {}

  IO.popen("losetup #{@loop_dev} #{vol}")
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
  
  IO.popen("losetup -d #{@loop_dev}")
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
  @info = {}
  @files_to_delete = []
  @clean_loopdev = false
  IO.popen("losetup -f") { |losetup_io| @loop_dev = losetup_io.read.chomp }
end


After do
  IO.popen("#{@tcplay} -u tcplay_test") unless @maps.empty?
  IO.popen("losetup -d #{@loop_dev}") if @clean_loopdev
end

