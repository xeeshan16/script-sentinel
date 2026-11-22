# Fixture site

A tiny static shop used by the quick start, the CI smoke test and `tests/test_examples.py`.
Everything here is synthetic: `cdn.vendor.test` and `js.payments.test` use the reserved
`.test` top-level domain and are never fetched as pages.

```bash
python -m http.server 8000 --bind 127.0.0.1 --directory examples/fixture-site
```

`robots.txt` disallows `/checkout`, which is common on real shops and shows why a site can
opt out of robots.txt for its own pages (`sentinel sites update NAME --ignore-robots`).
