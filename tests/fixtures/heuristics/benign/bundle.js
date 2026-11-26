// Typical bundled application code: lazy routes, an API client, storage for prefs.
// context: script_host=shop.example.test site=shop.example.test
// expect: none
const api = (path, init) => fetch(`/api/${path}`, init).then((r) => r.json());
const routes = { cart: () => import("./cart.js"), account: () => import("./account.js") };
export async function load(name) {
  const prefs = JSON.parse(localStorage.getItem("prefs") || "{}");
  const page = await routes[name]();
  return page.render(await api(name), prefs);
}
