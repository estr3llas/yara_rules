# README

some of the yara rules i've made for malware i've analysed over my career <br />
feel free to download and use in your own environment

```yara
import "pe"

rule DllInjection {
   meta:
     description = "Rule to detect Dll Injection in general"
   strings:
     $load_01 = "LoadLibraryA"
     $remote_01 = "NtCreateThreadEx"
   condition:
     uint16(0) == 0x5a4d and
     pe.imports("kernel32.dll", "OpenProcess") and/or
     pe.imports("kernel32.dll", "VirtualAllocEx") and
     pe.imports("kernel32.dll","WriteProcessMemory") and/or
     pe.imports("kernel32.dll", "LoadLibrary") and
     pe.imports("kernel32.dll", "GetProcAddress") and
     pe.imports("kernel32.dll","CreateRemoteThread") and/or
     all of them
}
```

```c++
OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
```
