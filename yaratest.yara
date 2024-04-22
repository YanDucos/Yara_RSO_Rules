rule eicar_av_test {
    /*
       Per standard, match only if entire file is EICAR string plus optional trailing whitespace.
       The raw EICAR string to be matched is:
       X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    */

    meta:
        description = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
        author = "Austin Byers | Airbnb CSIRT"
        reference = "http://www.eicar.org/86-0-Intended-use.html"

    strings:
        $eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

    condition:
        all of them
}

rule eicar_substring_test {
    /*
       More generic - match just the embedded EICAR string (e.g. in packed executables, PDFs, etc)
    */

    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}

rule rule_LockBit_Text {
    strings:
        $a1 = "\\LockBit_Ransomware.hta" wide fullword
        $a2 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell" wide fullword
        $a3 = "%s\\%02X%02X%02X%02X.lock" wide fullword
    condition:
        all of them
}

rule rule_LockBit_Bit {
    strings:
        $a1 = { 3C 8B 4C 18 78 8D 04 19 89 45 F8 3B C3 74 70 33 C9 89 4D F4 39 }
    condition:
        all of them
}

rule rule_LockBit_All {
    strings:
        $a1 = { 66 83 F8 61 72 ?? 66 83 F8 66 77 ?? 66 83 E8 57 EB ?? 66 83 F8 30 72 ?? 66 83 F8 39 77 ?? 66 83 E8 30 EB ?? }
        $a2 = { 8B EC 53 56 57 33 C0 8B 5D ?? 33 C9 33 D2 8B 75 ?? 8B 7D ?? 85 F6 74 ?? 55 8B 6D ?? 8A 54 0D ?? 02 D3 8A 5C 15 ?? 8A 54 1D ?? }
        $a3 = { 53 51 6A ?? 58 0F A2 F7 C1 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F0 0F C7 F2 59 5B C3 6A ?? 58 33 C9 0F A2 F7 C3 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F8 0F C7 FA 59 5B C3 0F 31 8B C8 C1 C9 ?? 0F 31 8B D0 C1 C2 ?? 8B C1 59 5B C3 }
        $b1 = { 6D 00 73 00 65 00 78 00 63 00 68 00 61 00 6E 00 67 00 65 00 00 00 73 00 6F 00 70 00 68 00 6F 00 73 00 }
        $b2 = "LockBit 3.0 the world's fastest and most stable ransomware from 2019" ascii fullword
        $b3 = "http://lockbit"
        $b4 = "Warning! Do not delete or modify encrypted files, it will lead to problems with decryption of files!" ascii fullword
    condition:
        2 of ($a*) or all of ($b*)
}
