from __future__ import annotations

import argparse
import base64
import ctypes as ct
import json
import os
import sqlite3
import sys
from configparser import ConfigParser
from pathlib import Path
from urllib.parse import urlparse

class SECItem(ct.Structure):
    _fields_ = [("type", ct.c_uint), ("data", ct.c_void_p), ("len", ct.c_uint)]
    def to_bytes(self) -> bytes: return ct.string_at(self.data, self.len)

def _find_nss() -> ct.CDLL:
    search = [
        os.getenv("NSS_LIB_PATH", ""),
        r"C:\Program Files\Mozilla Firefox",
        r"C:\Program Files (x86)\Mozilla Firefox",
        r"C:\Program Files\Thunderbird",
        r"C:\Program Files (x86)\Thunderbird",
        str(Path.home() / r"AppData\Local\Mozilla Firefox"),
    ]
    for base in search:
        dll = Path(base, "nss3.dll")
        if dll.is_file():
            os.add_dll_directory(dll.parent)
            return ct.CDLL(str(dll))
    print("[-] nss3.dll not found – install Firefox / Thunderbird.", file=sys.stderr)
    sys.exit(1)

class NSS:
    def __init__(self, profile: Path):
        self.nss = _find_nss()
        self.nss.NSS_Init.argtypes = [ct.c_char_p]
        self.nss.PK11_GetInternalKeySlot.restype = ct.c_void_p
        self.nss.PK11_CheckUserPassword.argtypes = [ct.c_void_p, ct.c_char_p]
        self.nss.PK11_NeedLogin.argtypes = [ct.c_void_p]
        self.nss.PK11SDR_Decrypt.argtypes = [ct.POINTER(SECItem), ct.POINTER(SECItem), ct.c_void_p]
        self.nss.SECITEM_ZfreeItem.argtypes = [ct.POINTER(SECItem), ct.c_int]

        if self.nss.NSS_Init(b"sql:" + str(profile).encode()):
            print(f"[-] NSS_Init failed on {profile}", file=sys.stderr)
            sys.exit(2)

        slot = ct.c_void_p(self.nss.PK11_GetInternalKeySlot())
        if self.nss.PK11_NeedLogin(slot):
            pwd = input("Primary Password: ").encode()
            if self.nss.PK11_CheckUserPassword(slot, pwd):
                print("[-] Wrong primary password.", file=sys.stderr)
                sys.exit(3)

    def decrypt(self, b64: str) -> str:
        blob = base64.b64decode(b64)
        inp = SECItem(0, ct.cast(ct.create_string_buffer(blob), ct.c_void_p), len(blob))
        out = SECItem()
        if self.nss.PK11SDR_Decrypt(ct.byref(inp), ct.byref(out), None):
            return "*** decryption failed ***"
        text = out.to_bytes().decode("utf-8", errors="replace")
        self.nss.SECITEM_ZfreeItem(ct.byref(out), 0)
        return text

def _all_profiles() -> list[Path]:
    """Return every profile folder mentioned in profiles.ini (may be invalid)."""
    ini = Path.home() / r"AppData\Roaming\Mozilla\Firefox\profiles.ini"
    if not ini.is_file():
        print("[-] profiles.ini not found – Firefox not installed?", file=sys.stderr)
        sys.exit(4)

    cfg = ConfigParser()
    cfg.read(ini, encoding="utf-8")

    profiles: list[tuple[Path, bool]] = [] 
    for sec in cfg.sections():
        if not sec.lower().startswith("profile"):
            continue
        raw = cfg.get(sec, "Path", fallback=None)
        if not raw:
            continue
        folder = (ini.parent / raw).expanduser()
        is_default = cfg.getboolean(sec, "Default", fallback=False)
        profiles.append((folder, is_default))

    if not profiles:
        print("[-] No profiles defined in profiles.ini", file=sys.stderr)
        sys.exit(5)

    # sort: default first, then the rest
    profiles.sort(key=lambda t: (not t[1], str(t[0]).lower()))
    return [p for p, _ in profiles]


def choose_profile(choice: str | None = None, list_only=False) -> Path:
    profs = _all_profiles()
    if list_only:
        for idx, p in enumerate(profs, 1):
            flag = "[default]" if idx == 1 else ""
            print(f"{idx}) {p} {flag}")
        sys.exit(0)

    if choice:
        try:
            idx = int(choice)
            return profs[idx - 1]
        except (ValueError, IndexError):
            print("[-] Invalid profile number.", file=sys.stderr)
            sys.exit(6)

    for p in profs:
        if (p / "key4.db").is_file():
            return p
    print("[-] No valid profile with key4.db found.", file=sys.stderr)
    sys.exit(7)


def read_logins(profile: Path):
    jfile = profile / "logins.json"
    if jfile.is_file():
        data = json.loads(jfile.read_text(encoding="utf-8"))
        for e in data.get("logins", []):
            yield e["hostname"], e["encryptedUsername"], e["encryptedPassword"], e.get("encType", 1)
        return

    sdb = profile / "signons.sqlite"
    if sdb.is_file():
        with sqlite3.connect(sdb) as conn:
            for row in conn.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins"):
                yield row
        return

    print(f"[-] No logins.json or signons.sqlite in {profile}", file=sys.stderr)
    sys.exit(8)


def dump_passwords(profile: Path, json_out=False):
    nss = NSS(profile)
    rows = []
    for url, enc_user, enc_pass, encType in read_logins(profile):
        user = nss.decrypt(enc_user) if encType else enc_user
        pwd  = nss.decrypt(enc_pass) if encType else enc_pass
        rows.append({"url": url, "user": user, "password": pwd})

    if json_out:
        json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print("url,user,password")
        for r in rows:
            print(f'{r["url"]},{r["user"]},{r["password"]}')

def main():
    ap = argparse.ArgumentParser(description="Decrypt Firefox/Thunderbird passwords (Windows only)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--list", action="store_true", help="List profiles and exit")
    g.add_argument("-c", "--choice", metavar="N", help="Profile number (see --list)")
    ap.add_argument("profile", nargs="?", help="Path to a profile folder")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of CSV")
    args = ap.parse_args()

    if args.profile:
        profile = Path(args.profile).expanduser()
        if not profile.is_dir():
            print(f"[-] {profile} is not a directory", file=sys.stderr)
            sys.exit(9)
    else:
        profile = choose_profile(choice=args.choice, list_only=args.list)

    dump_passwords(profile, json_out=args.json)

if __name__ == "__main__":
    main()
