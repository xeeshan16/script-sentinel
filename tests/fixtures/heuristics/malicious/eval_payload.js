// Synthetic test fixture: the decoded payload is a harmless no-op.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: obfuscation.decoded_code=high
eval(atob("dm9pZCAwOyAvKiBzeW50aGV0aWMgcGF5bG9hZCAqLw=="));
