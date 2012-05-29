#kernel32.dll
echo kernel32.dll
ruby getfunbyhash.rb duqu kernel32.dll kernel32.dll.mapped 0x88444BE9 0x92D66FBA 0xD1A588DB 0xFCAA0AB8 0xAE75A8DB 0xCF5350C5 0xDCAA4C9F 0x4BBFABB8 0xA668559E 0x4761BB27 0xD3E360E9 0x6B3749B3 0xD830E518 0x78C93963 0xD83E926D 0x19BD1298 0x6F8A172D 0xBF464446 0xAE16A0D4 0x3242AC18 0x479DE84E 0xB67F8157 0x2EAE2530

#psapi.dll
echo psapi.dll
ruby getfunbyhash.rb duqu psapi.dll psapi.dll.mapped 0xBCC7C0DA 

#advapi32.dll
echo advapi32.dll
ruby getfunbyhash.rb duqu advapi32.dll advapi32.dll.mapped 0x6012A950 0xC6151DC4 0xF03A2554 0x9C6E14F8 0x702B6244 0x2EDB7947 0x557DBBB6 0xE763A4A3

#version.dll
echo version.dll
ruby getfunbyhash.rb duqu version.dll version.dll.mapped 0xD4DE04DA 0xCEF01246

#userenv.dll
echo userenv.dll
ruby getfunbyhash.rb duqu userenv.dll userenv.dll.mapped 0x3E692063 0xAFF5F91F

#ntdll.dll
echo ntdll.dll
ruby getfunbyhash.rb duqu ntdll.dll ntdll.dll.mapped 0x40C4EC59 0x4FE2B7A2  0x5FC5AD65 0x1D127D2F 0x468B8A32 0xDB8CE88C 0x4143C970 0xFEA977E 0x7BCE6E19 0x8C6F89E1

