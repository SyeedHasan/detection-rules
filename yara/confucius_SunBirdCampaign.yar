rule Confucius_Sunbird_FEB21 {
	meta:
		author = "Syed Hasan"
		date = "2021/02/16"
		tlp = "red"
		description = "Detects the static file of the spyware used by Confucius operators in latest campaign against South Asian government offciials"
		
	strings:
		$s1 = "com.falconry.falconry" wide
		$s2 = "Falconry Connect"
	
	condition:
		all of them
}

rule Confucius_Sunbird_MEMORY_FEB21 {
	meta:
		author = "Syed Hasan"
		date = "2021/02/16"
		tlp = "red"
		description = "Spyware used by Confucius operators in latest campaign against South Asian government offciials"
		
	strings:
		$s1 = /SunServices\/\w+/
		$s2 = "AddFriend.class"
		$s3 = "FalcornyPics.class"
		
		$d1 = "ISFRIST"
		$d2 = "GAL"
		$d3 = "CLK"
		$d4 = "ClickedImageList.txt"
		$d5 = "callLog.db"
		$d6 = "contactdb.db"
		$d7 = "opratername" nocase
		$d8 = "dbstatus"
		$d9 = "StsrtService"
		$d10 = "Turn on Secure Phone Option Below..."
		
		$c1 = "Direcotory"
		$c2 = ".%0shdewboho/t@st$(ard)7?=!6n5e36sd8kj%&HiI!!!G98y/&%=?=*^%&ft4%("
		$c3 = "%da&/1@$(co)2?=!6n5e36thp:/sd8kj10%&Hiul!!!G987y/&%=?=*^%&ft4%(m"
		
		$z1 = /[\w+]{1,3}.zip/
	
	condition:
		2 of ($s*) and 6 of ($d*) and 1 of ($c*) and all of ($z*)
}