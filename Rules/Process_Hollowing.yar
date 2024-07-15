import "pe"

rule process_hollowing{
 strings:
  $1 = "CreateProcess" nocase wide ascii
  $2 = "UnmapViewOfSection" nocase wide ascii
  $3 = "VirtualAllocEx" nocase wide ascii
  $4 = "WriteProcessMemory" nocase wide ascii
  $5 = "ResumeThread" nocase wide ascii
 condition:
  all of them
}
