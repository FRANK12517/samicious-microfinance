# Browser smoke-test findings

## 2026-08-11/12 local preview

The local preview at `http://127.0.0.1:4173/index.html` rendered the SAMICIOUS MICROFINANCE login screen with the username field, password field, Enter System button, and login gallery controls visible. The protected-component runtime guard logged `All system integrity checks passed.` and no fatal JavaScript exception prevented the login screen from wiring.

The runtime hardening object reported `failClosed: true`, `protectedRpcGuard: true`, `duplicateMutationSuppression: true`, `sessionStorageAuthState: true`, and `uploadValidation: true`. Auth values were absent from both persistent `localStorage` and tab-scoped `sessionStorage` before login. The pre-login bootstrap attempt was denied by the new session guard and caught by the existing best-effort initialization path; this is expected fail-closed behavior.

The static audit initially reported a false-positive privileged-secret finding because its own detection regex contained the searched token. The regex was narrowed to actual privileged assignment patterns before the next browser reload. The visible login UI remained unchanged after this correction.


After the regex correction, the runtime audit returned an empty findings array. The hardening flags remained enabled and both persistent and tab-scoped session token values remained null before login. The initial visible-alert probe was a false positive caused by matching the application source text inside the document and script element; the actual protected-component console message remained `All system integrity checks passed.`


The final normalized source and generated build were reloaded at `http://127.0.0.1:4173/index.html?final=1`. The login UI rendered correctly. The console again reported `All system integrity checks passed.` The only warning was the expected pre-login fail-closed denial while anonymous bootstrap code attempted a protected data read; the existing best-effort initialization path caught it and continued to the login screen.
