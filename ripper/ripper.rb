require "metasm"
include Metasm
#developed by malware.lu team!!

class Spec
  attr_accessor :bin
  attr_accessor :addr
  attr_accessor :prototype
  attr_accessor :txref
  attr_accessor :tjtab
  attr_accessor :tlink
  attr_accessor :tspec
  attr_accessor :ecx
  def initialize (bin, addr, prototype, txref = [], tjtab = [], tlink = [], tspec = [], ecx = 0)
    @bin = bin
    @addr = addr
    @prototype = prototype
    @txref = txref
    @tjtab = tjtab
    @tlink = tlink
    @tspec = tspec
    @ecx = ecx
  end
end

class Ref
  attr_accessor :addr
  attr_accessor :len
  def initialize (addr, len)
    @addr = addr
    @len = len
  end
end

class Ripper

  attr_accessor :runner
  
  def initialize(tspec, debug=0)
    @runner = Class.new(DynLdr)
    tspec.each { |spec|
      rip(spec,debug)
    }
  end

  def decode_jtab(d, tjtab)
    asm = ""
    tjtab.each{ |jtab|
      asm << "xref_#{Expression[jtab.addr]}:\n"
      for i in 1..(jtab.len / 4)
        b = d.decode_int((jtab.addr) + i * 4, :u32)
        asm << "\tdd #{Expression[b]}\n"
      end
      asm << "\n"
    }
    return asm
  end

  def decode_xref(d, txref)
    asm = ""
    txref.each{ |xref|
      asm << "xref_#{Expression[xref.addr]}:\n\tdb '"
      for i in 1..(xref.len)
        b = d.decode_byte((xref.addr) + i)
        asm << "\\x#{b.ord}"
      end
      asm << "'\n"
    }
    return asm
  end

  def decode_tlink(d, asm, tlink)
    tlink.each{ |link|
       link_h="#{Expression[link.addr]}"
       asm = asm.gsub(link_h,"xref_"+link_h)
       asm << "xref_"+link_h+":\n\tdb '"
       for i in 0..(link.len)
         b = d.decode_byte((link.addr)+i)
         asm << "\\x#{b.to_s(16)}"
       end
       asm << "'\n"
    }
    return asm
  end

  def decode_xcall(asm, tspec)
    tspec.each{ |spec|
      asm = asm.gsub("thunk_#{spec.prototype}:","toto:")
      asm << "thunk_#{spec.prototype}:\n"
      asm << _rip(spec)
    }
    return asm
  end


  def _rip(spec, debug = 0)
    d = AutoExe.decode_file(spec.bin).init_disassembler
    asm = ''
    addr = d.normalize(spec.addr)
    d.disassemble_fast_deep(spec.addr)
    asm << d.flatten_graph(spec.addr).join("\n")
    asm << "\n"
    asm << decode_xref(d, spec.txref)
    asm << decode_jtab(d, spec.tjtab)
    asm = decode_xcall(asm, spec.tspec)
    asm = decode_tlink(d,asm, spec.tlink)
    if debug == 1
      #puts asm
      #puts ''
      value = ""; 12.times{value  << (65 + rand(25)).chr}
      File.open("/tmp/ouput."+value, 'w') do |f|
        f.puts asm
      end
      system("vi /tmp/ouput."+value)
      asm = ''
      File.open("/tmp/ouput."+value, "r") do |infile|
        while (line = infile.gets)
          asm << line
        end
      end
    end
    return asm
  end

  def rip(spec, debug = 0)
    asm  = ""
    if (spec.ecx != 0)
      asm << "mov ecx, #{@runner.str_ptr(spec.ecx)}\n"
    end
    asm << _rip(spec,debug)
    begin
      #@runner.parse_c ''
      @runner.new_func_asm spec.prototype, <<EOS
#{asm}
EOS
    rescue RuntimeError => e
      #Missing xref sould be addded in txref
      raise "Missing reference in #{spec.prototype}: #{e}"
    end
  end
end
