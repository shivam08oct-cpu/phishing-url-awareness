import re
from urllib.parse import urlparse

# Messages that represent status or informational output rather than security warnings
INFO_MESSAGES = (
    "No URL entered",
    "Could not identify",
    "No listed warning",
    "This text is not a valid URL format",
)


def has_warnings(findings: list[str]) -> bool:
    """Return True if findings contain genuine security warning signs."""
    if not findings:
        return False
    return not findings[0].startswith(INFO_MESSAGES)


def inspect_url(raw_url: str) -> list[str]:
    """Check visible URL text for selected warning signs."""
    url = raw_url.strip()
    findings = []

    # Step 1: Check for empty input
    if not url:
        return ["No URL entered."]

    # Step 2: Ensure scheme exists for parsing
    candidate = url if "://" in url else "http://" + url

    # Step 3: Parse the URL safely (Improvement C: handle malformed URLs)
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ["This text is not a valid URL format."]

    host = (parsed.hostname or "").lower()

    # Step 4: Validate hostname presence
    if not host:
        return ["Could not identify a hostname."]

    # Check 1: Suspicious @ symbol
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # Check 2: Unusually long URL
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # Check 3: IP address used as hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # Check 4: Excessive hostname segments/subdomains
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # Check 5: Punycode encoded hostname
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # Check 6: Plain unencrypted HTTP scheme
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    # Fallback if no warnings were triggered
    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings


def main():
    """Main interactive loop for the Phishing URL Awareness Checker."""
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")

    while True:
        try:
            raw_url = input("\nEnter a sample URL (or type q to quit): ")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye! Stay alert online.")
            break

        if raw_url.strip().lower() in ("q", "quit", "exit"):
            print("Goodbye! Stay alert online.")
            break

        findings = inspect_url(raw_url)

        print("\nResult:")
        for item in findings:
            print("- " + item)

        if has_warnings(findings):
            print(f"\nREVIEW CAREFULLY: {len(findings)} warning sign(s) found.")

        print("\nNever enter passwords from unexpected links.")


if __name__ == "__main__":
    main()
