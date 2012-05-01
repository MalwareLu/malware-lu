# include the magic ripper
require "ripper.rb"
# get a disassembler on first arq
disasm = AutoExe.decode_file(ARGV[0]).init_disassembler

specs = [Spec.new(0x40291D,
                  "int decrypt(char* in, char* out);")
        ]

worker = Ripper.new(disasm, specs)

for a in [0x1400, 0x140C, 0x143C, 0x1458]
  srcFile = File.open(ARGV[0], 'r')
  srcFile.seek(a, IO::SEEK_SET)
  src = srcFile.sysread(0x80)
  dst = "\x00" * (src.length)
  worker.runner.decrypt(src, dst)
  puts "#{a.to_s(16)}: #{dst}"
end
