import "pe"

rule manycam
{
    meta: 
        author = "estr3llas"
        note = "Probably Keylogger or Stealer"
        sha256 = "13b0b3145c873d4af932a06fa759de78fc662b913ace0369c7a0a26825772e0a"
        date = "12-23-2022"
    strings:
        $h1 = "{376A1D8E-C6FD-4c06-87BC-650C2B17850A}" wide
        $h2 = "%2\\protocol\\StdFileEditing\\server" wide
        $extension1 = "SOFTWARE\\Mozilla\\Firefox\\extensions" wide
        $extension2 = "SOFTWARE\\Microsoft\\Internet Explorer\\Extensions" wide
        $h3 = "command"
        $h4 = "Mozilla/5.0 (Windows NT 10; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0"
    condition:
        pe.imports("ADVAPI32.dll", "RegCreateKeyExW") and 3 of ($h*) and ($extension1 or $extension2)
}