require 'ffi'

module TCplayLib
  extend FFI::Library

  ffi_lib [ "#{ENV['BUILD_PATH'] || ".."}/libtcplay.so" ]

  TC_OK  = 0
  TC_ERR = -1
  TC_ERR_UNIMPL = -255

  callback :tc_api_cipher_iterator_fn, [ :pointer, :string, :int, :int], :int
  callback :tc_api_prf_iterator_fn, [ :pointer, :string], :int

  attach_function :tc_api_init, [ :int ], :int
  attach_function :tc_api_uninit, [ ], :int

  attach_function :tc_api_has, [ :string ], :int
  attach_function :tc_api_cipher_iterate, [ :tc_api_cipher_iterator_fn, :pointer ], :int
  attach_function :tc_api_prf_iterate, [ :tc_api_prf_iterator_fn, :pointer ], :int

  attach_function :tc_api_task_init, [ :string ], :pointer
  attach_function :tc_api_task_uninit, [ :pointer ], :int
  attach_function :tc_api_task_set, [ :pointer, :string, :varargs ], :int
  attach_function :tc_api_task_do, [ :pointer ], :int
  attach_function :tc_api_task_info_get, [ :pointer, :string, :varargs ], :int
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

