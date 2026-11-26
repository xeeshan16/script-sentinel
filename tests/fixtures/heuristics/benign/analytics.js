// A pageview tag that reports to its own host.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: none
(function (w, d) {
  var id = d.cookie.match(/_ex=([^;]+)/);
  var payload = JSON.stringify({ p: d.location.pathname, id: id && id[1] });
  if (navigator.sendBeacon) navigator.sendBeacon("https://cdn.vendor.test/collect", payload);
  else fetch("https://cdn.vendor.test/collect", { method: "POST", body: payload, keepalive: true });
})(window, document);
