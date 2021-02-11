import "pe"

rule confucius_avemaria_RAT {
    meta:
        author = "Syed Hasan"
        date = "2021-02-11"
        description = "Detects the Stage-II payload (Ave Maria) dropped by Confucius"
        hash = "A6E56C81C88FDAA28CBD3BF72635C5BECB164F75F51FF0AABD46EE7723D4AC23"

    strings:
        $s1 = "{A6D89F10-35F4-11D2-9375-00C04FD9757C}" ascii
        $s2 = "ForceRemove"

        $com1 = "AutoServer.EXE" wide
        $com2 = "val AppID = s {A6D89F10-35F4-11D2-9375-00C04FD9757C}" ascii
        $com3 = "AutoServer.AutoServ.1 = s 'AutoServ Class'"

    condition:
        all of ($com*) and
        all of ($s*) and
        uint16be(0) == 0x4D5A
}