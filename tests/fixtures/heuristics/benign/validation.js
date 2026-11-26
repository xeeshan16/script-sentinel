// Card number formatting and Luhn validation, entirely client-side.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: none
function luhn(value) {
  let sum = 0;
  const digits = value.replace(/\D/g, "").split("").reverse();
  digits.forEach((d, i) => { let n = Number(d); if (i % 2) { n *= 2; if (n > 9) n -= 9; } sum += n; });
  return sum % 10 === 0;
}
document.querySelector("#card-number").addEventListener("input", (e) => {
  e.target.setCustomValidity(luhn(e.target.value) ? "" : "Invalid card number");
});
