
rule Group21_DroppedPE_FEB21 {
	meta:
		author = "Syed Hasan"
		hash = "37C6026C74CA0DF996A2CCD303F1DEE6E73C46F2"
		description = "Detects Group 21's dropped PE"
		tlp = "White"

	strings:
		$cmd1 = "ipconfig /all"
		$cmd2 = "hostname"
		$cmd3 = "route print"
		$cmd4 = "net config"
		$cmd5 = "arp -A"
		$cmd6 = "netsh firewall"
		$cmd7 = "password"
		$cmd8 = "schtasks /CREATE"

		$s1 = "Response of Turkey to ISI Help"
		$s2 = "svechosts.exe"

		$o1 = "D:\\Project\\C++\\pend\\Release\\pend.pdb"
		$o2 = "f:\\dd\\vctools"
		$o3 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware"



	condition:
		uint16be(0) == 0x4D5A and 
		5 of ($cmd*) and
		1 of ($s*) and
		2 of ($o*)	


}