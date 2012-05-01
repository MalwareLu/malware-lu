require "metasm"
include Metasm


class Spec
  attr_accessor :addr
  attr_accessor :prototype
  attr_accessor :txref
  attr_accessor :tjtab
  attr_accessor :tlink
  def initialize (addr, prototype, txref = [], tjtab = [], tlink = [])
    @addr = addr
    @prototype = prototype
    @txref = txref
    @tjtab = tjtab
    @tlink = tlink
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
  
  def initialize(disasm, tspec, debug=0)
    @d = disasm
    @runner = Class.new(DynLdr)
    tspec.each { |spec|
      rip(spec,debug)
    }
  end

  def decode_jtab(tjtab)
    asm = ""
    tjtab.each{ |jtab|
      asm << "xref_#{Expression[jtab.addr]}:\n"
      for i in 1..(jtab.len / 4)
        b = @d.decode_int((jtab.addr) + i * 4, :u32)
        asm << "\tdd #{Expression[b]}\n"
      end
      asm << "\n"
    }
    return asm
  end

  def decode_xref(txref)
    asm = ""
    txref.each{ |xref|
      asm << "xref_#{Expression[xref.addr]}:\n\tdb '"
      for i in 1..(xref.len)
        b = @d.decode_byte((xref.addr) + i)
        asm << "\\x#{b.ord}"
      end
      asm << "'\n"
    }
    return asm
  end

  def decode_tlink(asm, tlink)
    tlink.each{ |link|
       link_h="#{Expression[link.addr]}"
       asm = asm.gsub(link_h,"xref_"+link_h)
       asm << "xref_"+link_h+":\n\tdb '"
       for i in 0..(link.len)
         b = @d.decode_byte((link.addr)+i)
         asm << "\\x#{b.to_s(16)}"
       end
       asm << "'\n"
    }
    return asm
  end

  def rip(spec,debug)
    asm = ''
    addr = @d.normalize(spec.addr)
    @d.disassemble_fast_deep(spec.addr)
    asm << @d.flatten_graph(spec.addr).join("\n")
    asm << "\n"
    asm << decode_xref(spec.txref)
    asm << decode_jtab(spec.tjtab)
    asm = decode_tlink(asm, spec.tlink)
    if debug == 1
      puts asm
      puts ''
    end
    
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
