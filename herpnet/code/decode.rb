#!/usr/bin/env ruby
# include the magic ripper
require "ripper.rb"
#string="uggc"
for a in [ 0x1AE88, 0x1AEF0, 0x1AF54, 0x1AF88, 0x1AFEC, 0x1B020, 0x1B084, 0x1B0B8, 0x1B0EC, 0x1B120, 0x1B184 ]
  srcFile = File.open(ARGV[0], 'r')
  srcFile.seek(a, IO::SEEK_SET)
  string = srcFile.sysread(0x20)
  specs = [Spec.new(ARGV[0], 0x403034,"unsigned int decode();", [], [], [], [], string)]
  worker = Ripper.new(specs)
  worker.runner.decode()
  puts string
end
