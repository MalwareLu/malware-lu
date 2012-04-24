# include the magic ripper
require "ripper.rb"
# get a disassembler on first arq
disasm = AutoExe.decode_file(ARGV[0]).init_disassembler
# Rip function at 0x40350E with signature int decrypt(char* text, int length, int* key);
specs = [Spec.new(0x40350E, "int decrypt(char* text, int length, int* key);")]
# Actually rip it
worker = Ripper.new(disasm, specs)
# Setup the arguments
length = 0x310C
offset = 0x5098
srcFile = File.open(ARGV[0], 'r')
srcFile.seek(offset, IO::SEEK_SET)
src = srcFile.sysread(length)
a = "\x00" * 4
# Launch the ripped function
worker.runner.decrypt(src, length, a)
# Output text in clear
File.open(ARGV[0] + ".0x#{offset.to_s(16)}.decrypted", 'w+'){|fd| fd << src}
