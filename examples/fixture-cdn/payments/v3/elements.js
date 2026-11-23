/*! Example Payments Elements v3 | synthetic fixture */
(function (w) {
  "use strict";
  function mount(selector) {
    var host = document.querySelector(selector);
    if (host) host.textContent = "[card field]";
  }
  w.ExamplePayments = { mount: mount };
})(window);
