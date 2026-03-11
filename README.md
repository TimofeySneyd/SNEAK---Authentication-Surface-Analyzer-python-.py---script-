# SNEAK
Authentication-Surface-Analyzer
Please see down below usage of this function script through command line launch:
C:\Ruby33\PROJECTS>python SNEAK.py https://wallettg.net
=======================================================
  S N E A K  —  Authentication Surface Analyzer
  Purpose: Pre‑2FA / Session / Logic Recon
=======================================================
[→ TARGET] https://wallettg.net
[✓ HTTP] Initial response 200

[ Session & Header Analysis ]
[! COOKIE] Cookies issued before authentication
    ↳ Check if cookies persist across auth / 2FA boundaries
[✓ COOKIE] __cf_bm → Secure, HttpOnly
[✓ SERVER] cloudflare

[ Authentication Surface Mapping ]
[! EXPOSED] /login → 200
    ↳ Primary login endpoint
    ↳ Potential IDOR or logic‑chain surface
[! EXPOSED] /auth → 200
    ↳ Auth gateway
    ↳ Potential IDOR or logic‑chain surface
[✓ LOCKED] /api/auth → 404
[✓ LOCKED] /api/login → 404
[! EXPOSED] /me → 200
    ↳ User identity endpoint
    ↳ Potential IDOR or logic‑chain surface
[! EXPOSED] /profile → 200
    ↳ Profile data endpoint
    ↳ Potential IDOR or logic‑chain surface
[! EXPOSED] /session → 200
    ↳ Session introspection
    ↳ Potential IDOR or logic‑chain surface

[ Pre‑2FA Content Inspection ]
[✗ LEAK] Sensitive keywords found: wallet
    ↳ If reachable pre‑2FA → ATO chain candidate

[ Analyst Notes ]
    ↳ ✓ Green  = expected / hardened
    ↳ ! Yellow = investigate / pivot
    ↳ ✗ Red    = high‑impact ATO signal
    ↳ SNEAK maps boundaries — it does NOT exploit
[✓ DONE] SNEAK analysis complete
