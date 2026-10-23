// Browser-side verifier for LOTM1 stat keys (no database required).
// Requires the public key exported from keys/stat_public.pem as SPKI DER base64.
// Never place stat_private.pem or any signing secret in the website.

const LOTM_PUBLIC_KEY_SPKI_BASE64 = "PASTE_PUBLIC_KEY_SPKI_BASE64_HERE";

function fromBase64Url(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  const binary = atob(b64);
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

function pemToBytes(pem) {
  const body = pem.replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "").replace(/\s/g, "");
  const binary = atob(body);
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

async function verifyLotmStatKey(keyText) {
  const parts = keyText.trim().split(".");
  if (parts.length !== 3 || parts[0] !== "LOTM1") {
    throw new Error("فرمت کلید معتبر نیست.");
  }

  // Paste the PEM public key into LOTM_PUBLIC_KEY_PEM, or convert it to SPKI base64.
  const publicKeyPem = window.LOTM_PUBLIC_KEY_PEM;
  if (!publicKeyPem || publicKeyPem.includes("PASTE_PUBLIC_KEY")) {
    throw new Error("کلید عمومی سایت هنوز تنظیم نشده است.");
  }

  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemToBytes(publicKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedBytes = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    fromBase64Url(parts[2]),
    signedBytes
  );
  if (!valid) throw new Error("امضای کلید معتبر نیست یا اطلاعات دست‌کاری شده است.");

  const payloadBytes = fromBase64Url(parts[1]);
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  if (!payload.expires_at || payload.expires_at < Math.floor(Date.now() / 1000)) {
    throw new Error("اعتبار این کلید به پایان رسیده است.");
  }
  return payload;
}

// Example:
// document.querySelector("#showStats").addEventListener("click", async () => {
//   try {
//     const data = await verifyLotmStatKey(document.querySelector("#statKey").value);
//     renderStats(data); // Build your Persian stat panel from the returned payload.
//   } catch (err) {
//     alert(err.message || "خطا در بررسی کلید");
//   }
// });
