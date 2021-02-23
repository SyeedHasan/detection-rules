rule LuckyElephant_FEB21 {
	
	meta:
		author = "Syed Hasan"
		description = "Detects the PE file dropped by LuckyElephant dropper"
		SHA1 = "15069cd6d0e55ba41e5e46221362772d2caea85d"
		tlp = "amber"

	strings:
		$s1 = "echo %d > c:\\windows\\temp\\tempval.tmp"
		$s2 = "HttpService.exe"
		$s3 = "FakeMutex"
		$s4 = "NTc2Nz"

		$pdb = "C:\\Users\\user\\source\\repos\\TestBed\\Release\\TestBed.pdb"
		$mutex = { 46 61 6B 65 4D 75 74 65 }

	condition:
		4 of them and uint16be(0) == 0x4D5A

}