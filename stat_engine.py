"""
LOTM RPG self-contained stat key engine.

The key contains a signed snapshot of a player's public stat panel. It does NOT
contain inventory contents or Telegram identifiers. No website database needed.

Install: pip install cryptography
Generate keys once: python stat_engine.py --init-keys
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent
KEY_DIR = ROOT / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "stat_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "stat_public.pem"
KEY_PREFIX = "LOTM1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def init_keys() -> None:
    """Create a long-lived RSA keypair. Keep the private key on the bot server only."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        raise FileExistsError(
            "A key file already exists. Back it up; do not silently replace signing keys."
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_bytes(public_bytes)
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass
    print(f"Created private key: {PRIVATE_KEY_PATH}")
    print(f"Created public key:  {PUBLIC_KEY_PATH}")
    print("IMPORTANT: copy stat_public.pem into the website; NEVER upload stat_private.pem.")


def _first(data: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [value]


def _clean(value: Any) -> Any:
    """Keep JSON-safe data and remove Telegram/private/inventory fields by design."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()
                if str(k).lower() not in {
                    "inventory", "inventory_id", "items", "telegram_id", "chat_id",
                    "user_id", "token", "password"
                }}
    return str(value)


def build_public_snapshot(player: Mapping[str, Any], *, issued_at: int | None = None,
                          expires_in: int = 30 * 24 * 60 * 60) -> dict[str, Any]:
    """
    Build the exact data the stat website may display.
    Adapt aliases here if the bot's player JSON uses different field names.
    Inventory and Telegram/account IDs are intentionally excluded.
    """
    now = int(time.time()) if issued_at is None else int(issued_at)

    identity = {
        "name": _first(player, "name", "first_name", default="Unknown"),
        "surname": _first(player, "surname", "last_name", default=""),
        "family": _first(player, "family", "family_name", default=""),
        "age": _first(player, "age"),
        "gender": _first(player, "gender"),
        "height": _first(player, "height"),
        "weight": _first(player, "weight"),
        "appearance": _first(player, "appearance"),
        "background": _first(player, "background"),
        "photo": _first(player, "photo", "photo_url"),
    }

    divine = {
        "rank": _first(player, "rank", "divine_rank", "god_rank", default="Mortal"),
        "type": _first(player, "type", "character_type", default=""),
        "main_pathways": _as_list(_first(player, "main_pathways", "pathways", "pathway")),
        "sequence_name": _first(player, "sequence_name", "sequence_title"),
        "sequence": _first(player, "sequence"),
        "extra_pathways": _as_list(_first(player, "extra_pathways", "additional_pathways")),
        "uniquenesses": _as_list(_first(player, "uniquenesses", "uniqueness")),
        "characteristics": _as_list(_first(player, "characteristics", "beyonder_characteristics")),
        "envisioning_pathways": _as_list(_first(player, "envisioning_pathways")),
        "envisioning_characteristics": _as_list(_first(player, "envisioning_characteristics")),
        "sefirot": _as_list(_first(player, "sefirot", "sefirah")),
        "faction": _first(player, "faction", "faction_name", default=""),
    }

    progress = {
        "anchor": _first(player, "anchor", default=0),
        "digestion_percent": _first(player, "digestion_percent", "digestion", default=0),
        "knowledge": _first(player, "knowledge", default=0),
        "experience": _first(player, "experience", default=0),
    }

    multipliers = {
        "final_digestion_multiplier": _first(
            player, "final_digestion_multiplier", "digestion_multiplier", default=1
        ),
        "anchor_loss_multiplier": _first(player, "anchor_loss_multiplier", default=1),
        "anchor_gain_multiplier": _first(player, "anchor_gain_multiplier", default=1),
    }

    attributes = {
        "physical_strength": _first(player, "physical_strength", "strength", default=0),
        "stamina": _first(player, "stamina", "endurance", default=0),
        "agility": _first(player, "agility", default=0),
        "spirituality": _first(player, "spirituality", "spirit", default=0),
        "intelligence": _first(player, "intelligence", "intellect", default=0),
        "combat_intelligence": _first(
            player, "combat_intelligence", "battle_intelligence", default=0
        ),
        "talent": _first(player, "talent", default=0),
    }

    location = {
        "city": _first(player, "city_name", "city"),
        "area": _first(player, "area_name", "area"),
        "location": _first(player, "location_name", "location"),
    }

    return _clean({
        "schema": 1,
        "issued_at": now,
        "expires_at": now + max(60, int(expires_in)),
        "identity": identity,
        "divine_status": divine,
        "progress": progress,
        "multipliers": multipliers,
        "attributes": attributes,
        "location": location,
    })


def generate_stat_key(player: Mapping[str, Any], *, expires_in: int = 30 * 24 * 60 * 60) -> str:
    """Return LOTM1.<base64url-json>.<base64url-rsa-signature>."""
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError("Missing signing key. Run: python stat_engine.py --init-keys")
    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    payload = build_public_snapshot(player, expires_in=expires_in)
    payload_bytes = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    encoded_payload = b64u(payload_bytes)
    signed_message = f"{KEY_PREFIX}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(
        signed_message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{KEY_PREFIX}.{encoded_payload}.{b64u(signature)}"


def verify_stat_key_locally(key: str) -> dict[str, Any]:
    """Optional server-side verification helper; the website verifies with the public key."""
    parts = key.strip().split(".")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        raise ValueError("Invalid key format")
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError("Missing public key")
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    message = f"{parts[0]}.{parts[1]}".encode("ascii")
    public_key.verify(b64u_decode(parts[2]), message, padding.PKCS1v15(), hashes.SHA256())
    payload = json.loads(b64u_decode(parts[1]).decode("utf-8"))
    if int(payload.get("expires_at", 0)) < int(time.time()):
        raise ValueError("This stat key has expired")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-keys", action="store_true", help="Create RSA signing keypair")
    parser.add_argument("--demo", action="store_true", help="Print a demo key using example stats")
    args = parser.parse_args()
    if args.init_keys:
        init_keys()
        return
    if args.demo:
        example = {
            "name": "Klein", "surname": "Moretti", "family": "N/A",
            "rank": "Beyonder", "pathway": "Fool", "sequence": 9,
            "characteristics": ["Fool Sequence 9 Characteristic"],
            "anchor": 100, "digestion_percent": 0, "knowledge": 0, "experience": 0,
            "physical_strength": 10, "stamina": 10, "agility": 10, "spirituality": 10,
            "intelligence": 10, "combat_intelligence": 10, "talent": 10,
            "city_name": "Tingen", "area_name": "East Borough", "location_name": "Unknown",
            "inventory": ["THIS MUST NOT APPEAR"],
        }
        key = generate_stat_key(example)
        print(key)
        print("\nVerified payload:")
        print(json.dumps(verify_stat_key_locally(key), ensure_ascii=False, indent=2))
        return
    parser.print_help()


if __name__ == "__main__":
    main()
