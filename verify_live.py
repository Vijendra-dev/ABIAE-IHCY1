import httpx

print("=== Defend AI - Live Service Verification ===\n")

h = httpx.get("http://127.0.0.1:8000/health").json()
print("Backend:    ", h["status"], "| v" + h["version"])

t = httpx.get("http://127.0.0.1:8001/health").json()
print("TrustLens: ", t["status"], "|", t["service"])

print("\n--- Inspecting: paypa1-secure-login.com ---")
r = httpx.post("http://127.0.0.1:8000/scans/inspect-url", json={"url": "https://paypa1-secure-login.com"}, timeout=15)
d = r.json()
print("Target:     ", d["target"])
print("Brand:      ", d["brand_detected"], "(" + str(round(d["similarity_score"] * 100)) + "% match)")
print("Trust Score:", d["trust_score"], "/ 100")
print("Risk Score: ", d["risk_score"], "/ 100 (" + d["risk_level"] + ")")
print("Reasons:")
for reason in d["reasons"]:
    print("  -", reason)
print("Antigravity:", d["antigravity_event_id"])

print("\n--- Inspecting: google.com ---")
r2 = httpx.post("http://127.0.0.1:8000/scans/inspect-url", json={"url": "https://google.com"}, timeout=15)
d2 = r2.json()
print("Target:     ", d2["target"])
print("Brand:      ", d2["brand_detected"], "(" + str(round(d2["similarity_score"] * 100)) + "% match)")
print("Risk Score: ", d2["risk_score"], "/ 100 (" + d2["risk_level"] + ")")

print("\n=== All systems operational! ===")
print("Open your browser at: http://127.0.0.1:8000/")
