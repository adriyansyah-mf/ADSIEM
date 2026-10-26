rule AI_Stage2_Loader_aaaaaaaa
{
    meta:
        description = "AI-drafted rule from investigation evidence"
        author = "AI draft requested by ana"
        date = "2026-10-26"
        case = "d404960f-d918-4785-8a08-a774761d4510"
        investigation = "27ed4965-f5ef-430d-a76f-22641b420a6f"
        sample_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        confidence = 85
        tags = "loader"
        mitre = "T1055"
        status = "draft - disabled until validated and tested"
    strings:
        $pdb = "C:\\build\\stage2\\loader.pdb"
        $mutex = "Global\\s2_mtx_91" wide ascii
        $ua = "Mozilla/5.0 (s2\"loader)" nocase
        $hex = { 4D 5A ?? 90 [2-4] 50 45 }
        $re = /stage2_[0-9a-f]{8}\.dat/
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and 2 of them
}
