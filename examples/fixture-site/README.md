# Fixture site

A tiny static shop and the "third-party" CDN it loads scripts from, used by the quick
start, the CI smoke test and `tests/test_examples.py`. Everything here is synthetic.

```bash
python examples/serve.py    # shop on http://127.0.0.1:8000, CDN on http://127.0.0.1:8001
```

- `fixture-site/` is the shop. `{{CDN}}` in its HTML is replaced with the CDN's origin, and
  its pages are served with a few security headers (the checkout page also gets a
  report-only CSP), so scans have headers to record.
- `../fixture-cdn/` plays the vendors: an analytics tag and a payments library. The checkout
  page pins the payments library with a real `integrity` value. Files are read on every
  request, so editing one simulates a vendor shipping a new version.
- `robots.txt` disallows `/checkout`, which is common on real shops and shows why a site can
  opt out of robots.txt for its own pages (`sentinel sites update NAME --ignore-robots`).
