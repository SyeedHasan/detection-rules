import "pe"

rule warzoneRAT_NOV20 {
	meta:
		author = "Syed Hasan"
		date = "2021/02/16"
		description = "Detects the Warzone RAT belonging to the AveMaria malware"
		hash = "90001df66b709685e2654b9395f8ce67e9b070cbaa624d001a7dd2adbc8d8eda"
	strings:
		$s1 = "C:\\Users\\Vitali Kremez\\Documents\\MidgetPorn\\workspace\\MsgBox.exe" wide
		$s2 = "warzone160"
		$s3 = "Ave_Maria Stealer" wide
		$s4 = "OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide
		$s5 = "Elevation:Administrator!new" wide
		$s6 = "Asend.db"
		$s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList"
		$s8 = "\\sqlmap.dll" wide fullword

		$cmd1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q"
		$cmd2 = "root\\CIMV2" wide
		$cmd3 = "select signon_realm, origin_url, username_value, password_value from wow_logins"
		$cmd4 = "\\programs.bat" wide
		$cmd5 = "/n:%temp%\\ellocnak.xml" wide
		$cmd6 = "wmic process call create"
		$cmd7 = "powershell Add-MpPreference -ExclusionPath"

		$MZ = "This program cannot be run in DOS mode."

	condition:
		5 of ($s*) and 4 of ($cmd*) and
		( pe.resources[0].id == 102 or ($MZ in (pe.resources[0].offset..pe.resources[0].offset + pe.resources[0].length))) and
		( uint16be(0) == 0x4D5A and filesize > 110KB )

}