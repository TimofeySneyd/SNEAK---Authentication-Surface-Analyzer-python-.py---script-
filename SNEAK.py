import sys
import requests
from urllib.parse import urljoin

# ========= COLOR SETUP =========
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def c(text, color):
    if not COLOR:
        return text
    return color + text + Style.RESET_ALL

GREEN = Fore.GREEN if COLOR else ""
YELLOW = Fore.YELLOW if COLOR else ""
RED = Fore.RED if COLOR else ""
BLUE = Fore.CYAN if COLOR else ""
GRAY = Fore.LIGHTBLACK_EX if COLOR else ""

# ========= UI =========
def banner():
    print("=" * 55)
    print("  S N E A K  —  Authentication Surface Analyzer")
    print("  Purpose: Pre‑2FA / Session / Logic Recon")
    print("=" * 55)

def signal(color, tag, msg):
    icon = {
        GREEN: "✓",
        YELLOW: "!",
        RED: "✗",
        BLUE: "→",
        GRAY: "·"
    }.get(color, "*")

    print(c(f"[{icon} {tag}]", color), msg)

def explain(text):
    print(c("    ↳ " + text, GRAY))

# ========= CORE =========
def base_request(target):
    signal(BLUE, "TARGET", target)
    try:
        r = requests.get(
            target,
            timeout=10,
            allow_redirects=True,
            headers={"X-H1-traffic": "research"}
        )
        signal(GREEN, "HTTP", f"Initial response {r.status_code}")
        return r
    except Exception as e:
        signal(RED, "ERROR", str(e))
        sys.exit(1)

def analyze_headers(resp):
    print("\n[ Session & Header Analysis ]")

    headers = resp.headers

    if "Set-Cookie" in headers:
        signal(YELLOW, "COOKIE", "Cookies issued before authentication")
        explain("Check if cookies persist across auth / 2FA boundaries")

        for ckie in resp.cookies:
            flags = []
            if ckie.secure:
                flags.append("Secure")
            if ckie.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly")

            if not flags:
                signal(RED, "COOKIE", f"{ckie.name} → NO FLAGS")
                explain("Possible session fixation or JS access")
            else:
                signal(GREEN, "COOKIE", f"{ckie.name} → {', '.join(flags)}")
    else:
        signal(GREEN, "COOKIE", "No cookies issued pre‑auth")

    server = headers.get("Server")
    if server:
        signal(GREEN, "SERVER", server)
    else:
        signal(GRAY, "SERVER", "Not disclosed")

def auth_surface_scan(base):
    print("\n[ Authentication Surface Mapping ]")

    paths = {
        "/login": "Primary login endpoint",
        "/auth": "Auth gateway",
        "/api/auth": "API auth handler",
        "/api/login": "API login endpoint",
        "/me": "User identity endpoint",
        "/profile": "Profile data endpoint",
        "/session": "Session introspection"
    }

    for path, meaning in paths.items():
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=8)
            if r.status_code < 400:
                signal(YELLOW, "EXPOSED", f"{path} → {r.status_code}")
                explain(meaning)
                explain("Potential IDOR or logic‑chain surface")
            else:
                signal(GREEN, "LOCKED", f"{path} → {r.status_code}")
        except:
            signal(RED, "ERROR", f"{path} unreachable")

def pre_2fa_content_check(target):
    print("\n[ Pre‑2FA Content Inspection ]")

    try:
        r = requests.get(target, timeout=10)
        body = r.text.lower()

        keywords = ["token", "session", "userid", "wallet", "balance"]
        hits = [k for k in keywords if k in body]

        if hits:
            signal(RED, "LEAK", f"Sensitive keywords found: {', '.join(hits)}")
            explain("If reachable pre‑2FA → ATO chain candidate")
        else:
            signal(GREEN, "CLEAN", "No sensitive keywords in response body")
    except Exception as e:
        signal(RED, "ERROR", str(e))

def analyst_notes():
    print("\n[ Analyst Notes ]")
    explain("✓ Green  = expected / hardened")
    explain("! Yellow = investigate / pivot")
    explain("✗ Red    = high‑impact ATO signal")
    explain("SNEAK maps boundaries — it does NOT exploit")

# ========= MAIN =========
def main():
    banner()

    if len(sys.argv) != 2:
        print("Usage: python SNEAK.py https://target")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith("http"):
        target = "https://" + target

    resp = base_request(target)
    analyze_headers(resp)
    auth_surface_scan(target)
    pre_2fa_content_check(target)
    analyst_notes()

    signal(GREEN, "DONE", "SNEAK analysis complete")

if __name__ == "__main__":
    main()