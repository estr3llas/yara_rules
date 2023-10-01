import "pe"

rule bruteratelc4 {
    meta:
        author = "spyw4re"
        Date = "2023-10-01"
        hash1 = "d71dc7ba8523947e08c6eec43a726fe75aed248dfd3a7c4f6537224e9ed05f6f"
        hash2 = "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd40abfe4ea8f318d37bbe.exe"
        decription = "A Rule to detect brute ratel stager payloads."
    
    strings:
        $api_hashing = {ac 84 c0 74 07 c1 cf 0d 01 c7 eb f4}
        $push_stack = {50 68 ?? ?? ?? ??}
    
    condition:
        (uint16(0) == 0x5A4D) and all of them
}  

