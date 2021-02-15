rule FASTCASH_Lazarus_2020{
	meta:
		author = "Syed Hasan"
		date = "2021-02-15"
		SHA256 = "39CBAD3B2AAC6298537A85F0463453D54AB2660C913F4F35BA98FFFEB0B15655"
		description = "Sample from Lazarus' FastCash campaign"
	strings:
		$s1 = "C:\\Intel\\tmp3AC.tmp"
		$s2 = "[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s\n"

		$regex1 = /(Injection|Ejection) : [\w+ ]+/ 

	condition:
		all of ($s*) and all of ($regex*)

}