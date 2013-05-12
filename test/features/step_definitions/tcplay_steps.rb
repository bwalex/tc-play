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

  IO.popen("losetup #{@loop_dev} #{vol}")
  IO.popen("#{@tcplay} #{@args.join(' ')}", mode='r+') do |tcplay_io|
    tcplay_io.expect "Passphrase:", 10 do
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


Then /^I expect dmsetup to have the following tables:$/ do |tables|
  tables.map_headers! { |h| h.to_sym }
  tables.diff!(@maps)
end

Before do
  @tcplay = "../tcplay"
  @maps = []
  IO.popen("losetup -f") { |losetup_io| @loop_dev = losetup_io.read.chomp }
end

After do
  IO.popen("#{@tcplay} -u tcplay_test") unless @maps.empty?
  IO.popen("losetup -d #{@loop_dev}")
end


#@maps = []
#IO.popen("dmsetup table") do |dmsetup_io|
#  dmsetup_io.each do |line|
#    line.match(/^(.*):\s+(\d+)\s+(\d+)\s+crypt\s+([^\s]+)\s+([a-fA-F0-9]+)\s+(\d+)\s+[^\s]+\s+(\d+)/) do |m|
#      c = m.captures
#      map = {
#        :name       => c[0],
#        :begin      => c[1],
#        :end        => c[2],
#        :algo       => c[3],
#        :key        => c[4],
#        :offset     => c[5],
#        :iv_offset  => c[6]
#      }
#      maps << map
#    end
#  end
#end

#maps.each do |map|
#  puts "map: #{map}"
#end
