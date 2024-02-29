rule vidar_stealer {
	meta:
		author = "estrellas"
    date = "02-29-24"
    description = "Those bytes refer to vidar's decryption routine"
	strings:
		$dec = { 8B C8 8B 45 FC 33 D2 F7 F1 8B 45 0C 8B 4D F4 C7 04 24 ?? ?? ?? ?? 8A 04 02 32 04 19 88 03 FF D7 }
	condition:
		uint16(0) == 0x5a4d and $dec
}
