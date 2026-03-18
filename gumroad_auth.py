import os
import httpx


async def verify_license(license_key: str) -> dict:
    """Verify a Gumroad license key. Returns {success, email, uses, error}."""
    if os.getenv("DEV_MODE", "").lower() == "true":
        return {"success": True, "email": "dev@test.com", "uses": 0}

    if not license_key or not license_key.strip():
        return {"success": False, "error": "License key is required"}

    product_id = os.getenv("GUMROAD_PRODUCT_ID", "")
    if not product_id:
        return {"success": False, "error": "Product not configured"}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            "https://api.gumroad.com/v2/licenses/verify",
            data={
                "product_id": product_id,
                "license_key": license_key.strip(),
                "increment_uses_count": "true",
            },
        )
        data = resp.json()

    if not data.get("success"):
        return {"success": False, "error": data.get("message", "Invalid license key")}

    purchase = data.get("purchase", {})
    return {
        "success": True,
        "email": purchase.get("email", ""),
        "uses": data.get("uses", 0),
    }
