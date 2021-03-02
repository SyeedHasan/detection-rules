rule DoNot_MAR21 {
	meta:
		author = "Syed Hasan"
		description = "Detect DoNot PE"
		hash = "bd14449b6c0c4b486d7a931b3d728050fa84800e"
		date = "2021/03/02"
		tlp = "white"

	strings:
		$s1 = "USERNAME"
		$s2 = "%s\\initqs.bat"
		$s3 = "Copy Right"
		$s4 = "system core pvt ltd"
		$s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0" wide
		$s6 = "Temfile"
		$s7 = "plaile"
		$s8 = "pyfile"
		$s9 = "hynos"
		$s10 = "wuaupgs"
		$s11 = "ACONOUT$"
		$s12 = "ren"
		$s13 = "writing failed!"
		$s14 = "something went wrong!!!"

		$u1 = "%s\\ty67nui8uhyh"
		$u2 = "otlu4vxotzkx{vjgzky4utrotk"
		$u3 = "/%s/Xddv21SDsxDl"
		$u4 = "\\ty67nui8uhyh"
		
	condition:
		1 of ($u*) and 
		6 of ($s*) and
		uint16be(0) == 0x4D5A

}