rule Suspicious_Test_String
{
    meta:
        description = "Test rule used only by clamav-scanner tests, not real malware detection"
    strings:
        $a = "malicious-test-string-for-yara-testing" xor
    condition:
        $a
}