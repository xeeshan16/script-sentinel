// A tag manager loading its own container from its own host.
// context: script_host=tags.vendor.test site=shop.example.test
// expect: none
(function (d, id) {
  var s = d.createElement("script");
  s.async = true;
  s.src = "https://tags.vendor.test/c/" + id + ".js";
  d.head.appendChild(s);
})(document, "GT-12345");
