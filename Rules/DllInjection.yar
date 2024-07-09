import "pe"

rule DllInjection {
   meta:
     description = "Rule to detect Dll Injection in general"
   strings:
     $load_01 = "LoadLibraryA"
     $remote_01 = "NtCreateThreadEx"
   condition:
     uint16(0) == 0x5a4d and
     pe.imports("kernel32.dll", "OpenProcess") and
     pe.imports("kernel32.dll", "VirtualAllocEx") and
     pe.imports("kernel32.dll","WriteProcessMemory") and
     pe.imports("kernel32.dll", "LoadLibrary") and
     pe.imports("kernel32.dll", "GetProcAddress") and
     pe.imports("kernel32.dll","CreateRemoteThread") and
     all of them
}
