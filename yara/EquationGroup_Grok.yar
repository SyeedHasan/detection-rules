rule APT_US_EquationGroup_GROK {

    meta:
        author = "Syed Hasan"
        description = "Yara rule to detect Equation Group's GROK"
        tlp = "white"
        hash = "441f2a6775621af8c5d1ead7082e9573ad878bc90675ed55f86abfc8a9e8cc6f"

    strings:
        $pdb = "c:\\users\\rmgree5\\co\\standalonegrok_2.1.1.1\\gk_driver\\gk_sa_driver\\objfre_wnet_amd64\\amd64\\SaGk.pdb"

        $s1 = "R0omp4ar"
        $s2 = "Dl_unxwin"
        $s3 = "rin0r_"
        $s4 = "msrtdv.sys" wide

        $f1 = "MSRTdv interface driver" wide
        $f2 = "5.1.1364.6430" wide
        
        $r1 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion"
        $r2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment"

    condition:
        uint16(0) == 0x5a4d and
        (
            $pdb or 
            (
                1 of ($r*) and 
                1 of ($f*)  
            ) or 
            3 of ($s*)
        )

}