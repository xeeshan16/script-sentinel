// A measurement tag that reports to its vendor's separate collection host.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: exfil.outbound=low
(function () {
  var t = performance.now();
  addEventListener("pagehide", function () {
    navigator.sendBeacon("https://metrics.vendor-collect.test/v1", String(performance.now() - t));
  });
})();
