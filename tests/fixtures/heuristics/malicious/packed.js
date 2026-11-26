// Synthetic test fixture: a packed no-op.
// context: script_host=cdn.vendor.test site=shop.example.test
// expect: obfuscation.packed=medium obfuscation.dynamic_code=medium
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('0 1',2,2,'void|0'.split('|'),0,{}))
