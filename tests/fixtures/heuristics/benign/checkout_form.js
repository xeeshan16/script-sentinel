// First-party checkout code posting to the site's own API.
// context: script_host=shop.example.test site=shop.example.test
// expect: none
const form = document.getElementById("payment-form");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = new FormData(form);
  const response = await fetch("/api/checkout", { method: "POST", body });
  document.querySelector("#status").textContent = response.ok ? "Paid" : "Failed";
});
form.querySelectorAll("input").forEach((input) => {
  input.addEventListener("input", () => input.classList.remove("invalid"));
});
