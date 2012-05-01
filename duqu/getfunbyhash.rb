# include the magic ripper
require "ripper.rb"
# get a disassembler on first arg
disasm = AutoExe.decode_file(ARGV[0]).init_disassembler
# Rip function at 0x401BCE with signature int decrypt(char* in, char* in);
specs = [Spec.new(0x401BCE,"unsigned int getfun(char* in, unsigned int hash);")]
worker = Ripper.new(disasm, specs)
# Decode exports
pe = Metasm::PE.decode_file_header(ARGV[1])
pe.decode_exports
# for each provided hash
for hash in ARGV[3..ARGV.length]
  # Get the mapped dll
  srcFile = File.open(ARGV[2], 'r')
  src = srcFile.read()
  # Get the rva from duqu code
  rva = worker.runner.getfun(worker.runner.str_ptr(src), hash.hex) - worker.runner.str_ptr(src)
  # Search for the name in exports 
  pe.export.exports.each { |exp|
    if exp.target_rva == rva
      puts "#{hash}:#{exp.name}"
    end
  }
end
