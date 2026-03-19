import os
import httpx


async def verify_license(license_key: str, tier: str = "report") -> dict:
    """Verify a Gumroad license key. Returns {success, email, uses, tier, error}.

    tier: "report" or "fixpack" — determines which product ID to check against.
    If the key doesn't match the requested tier, it tries the other tier too.
    """
    if os.getenv("DEV_MODE", "").lower() == "true":
        return {"success": True, "email": "dev@test.com", "uses": 0, "tier": tier}

    if not license_key or not license_key.strip():
        return {"success": False, "error": "License key is required"}

    product_ids = {
        "report": os.getenv("GUMROAD_REPORT_PRODUCT_ID", ""),
        "fixpack": os.getenv("GUMROAD_FIXPACK_PRODUCT_ID", ""),
    }

    # Try the requested tier first, then fall back to the other
    tiers_to_try = [tier] + [t for t in product_ids if t != tier]

    for try_tier in tiers_to_try:
        pid = product_ids.get(try_tier, "")
        if not pid:
            continue

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.gumroad.com/v2/licenses/verify",
                data={
                    "product_id": pid,
                    "license_key": license_key.strip(),
                    "increment_uses_count": "true",
                },
            )
            data = resp.json()

        if data.get("success"):
            purchase = data.get("purchase", {})
            return {
                "success": True,
                "email": purchase.get("email", ""),
                "uses": data.get("uses", 0),
                "tier": try_tier,
            }

    return {"success": False, "error": "Invalid license key"}
