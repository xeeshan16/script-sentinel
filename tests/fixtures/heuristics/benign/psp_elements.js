// A payment provider's card fields, tokenized against its own API.
// context: script_host=pay.vendor.test site=shop.example.test
// expect: none
(function (w) {
  function tokenize(form) {
    var pan = form.querySelector("[autocomplete=cc-number]").value;
    var cvc = form.querySelector("[autocomplete=cc-csc]").value;
    return fetch("https://pay.vendor.test/v1/tokens", {
      method: "POST",
      body: JSON.stringify({ number: pan, cvc: cvc })
    }).then(function (r) { return r.json(); });
  }
  w.ExamplePay = { tokenize: tokenize };
})(window);
