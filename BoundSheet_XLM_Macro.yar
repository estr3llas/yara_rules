rule BoundSheet_XLM_Macro 
{
  meta: 
        author = "spyw4re"
        note = "Rule to detect presence of hidden sheets in .xls/.xlsx files" 
        date = "25-05-2023"
  strings:
        $ole_magic = {D0 CF 11 E0 A1 B1 1A E1}
        $h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
        $h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
  condition:
        $ole_magic and ($h1 or $h2)
}
