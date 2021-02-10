import "pe"

rule njRatDroppedPE {
    meta:
        description = "Detects the stage-II PE file dropped by the njRat malware"
        author = "Syed Hasan"
        date = "2021-02-10"
        hash = "59d6a7b7a5b105e7b8e16dce38d40a00"
        status = "Experimental"
    strings:
        $versionInfo = "k.exe"
        $modifiedName = "server.exe" wide
        $persistenceMech = "software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $connInfo = "127.0.0.1:7777,moskvin-60506.portmap.io:60506:60000," wide

    condition:
        all of them and (
            uint16be(0) == 0x4D5A and
            pe.imports("mscoree.dll", "_CorExeMain")
        )
}