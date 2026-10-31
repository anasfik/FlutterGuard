#!/usr/bin/env python3
"""Upload a built FlutterGuard release to Google Play without a toolchain.

Play Developer API v3 only exposes `applications/<pkg>/...`, so the app itself
must already exist in Play Console; this script does everything after that:
bundle upload, track release + notes, store listing text, and images.

Auth is a service-account JSON key (Play Console -> Users and permissions must
invite the key's client_email first). No google-api-python-client needed:
pyjwt signs the assertion, urllib does the rest.

  export PLAY_SA_JSON=~/path/to/play-sa.json
  ./upload.py bundle  --aab ../app/build/outputs/bundle/release/app-release.aab \
                      --track internal --notes-file release-notes.txt
  ./upload.py listing --short "Offline security audit for Flutter apps." --full-file full.txt
  ./upload.py images  --type phoneScreenshots --files screenshots/*.png
"""
import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt  # pyjwt

API = "https://androidpublisher.googleapis.com/androidpublisher/v3"
UPLOAD = "https://androidpublisher.googleapis.com/upload/androidpublisher/v3"
SCOPE = "https://www.googleapis.com/auth/androidpublisher"


def token(key_path: str) -> str:
    """Mint a short-lived access token from a service-account key."""
    key = json.loads(pathlib.Path(key_path).read_text())
    now = int(time.time())
    assertion = jwt.encode(
        {
            "iss": key["client_email"],
            "scope": SCOPE,
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        },
        key["private_key"],
        algorithm="RS256",
    )
    body = urllib.parse.urlencode(
        {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
    ).encode()
    with urllib.request.urlopen("https://oauth2.googleapis.com/token", body) as r:
        return json.load(r)["access_token"]


class Play:
    def __init__(self, key_path: str, pkg: str):
        self.pkg = pkg
        self.tok = token(key_path)
        self.edit = None

    def call(self, method: str, url: str, payload=None, raw=None, headers=None):
        hdrs = {"Authorization": f"Bearer {self.tok}"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs["Content-Type"] = "application/json"
        if raw is not None:
            data = raw
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:600]
            sys.exit(f"HTTP {e.code} on {method} {url}\n{detail}")

    # ---- edits ---------------------------------------------------------
    def open_edit(self):
        if self.edit is None:
            self.edit = self.call("POST", f"{API}/applications/{self.pkg}/edits")["id"]
        return self.edit

    def commit(self):
        r = self.call(
            "POST", f"{API}/applications/{self.pkg}/edits/{self.open_edit()}:commit"
        )
        self.edit = None
        return r

    # ---- operations ----------------------------------------------------
    def upload_bundle(self, aab: pathlib.Path, track: str, notes: str, status: str):
        edit = self.open_edit()
        # The resumable session URI is returned in the Location *header* and the
        # body is empty. One request: requesting twice leaves an orphan session.
        req = urllib.request.Request(
            f"{UPLOAD}/applications/{self.pkg}/edits/{edit}/bundles?uploadType=resumable",
            data=b"{}",
            headers={
                "Authorization": f"Bearer {self.tok}",
                "X-Upload-Content-Type": "application/octet-stream",
                "X-Upload-Content-Length": str(aab.stat().st_size),
                "Content-Type": "application/json; charset=UTF-8",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                location = r.headers["Location"]
        except urllib.error.HTTPError as e:
            sys.exit(f"HTTP {e.code} opening upload session\n{e.read().decode(errors='replace')[:600]}")
        req = urllib.request.Request(
            location,
            data=aab.read_bytes(),
            headers={"Content-Type": "application/octet-stream"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=600) as r:
            version_code = json.loads(r.read())["versionCode"]
        self.call(
            "PUT",
            f"{API}/applications/{self.pkg}/edits/{edit}/tracks/{track}",
            {
                "track": track,
                "releases": [
                    {
                        "versionCodes": [str(version_code)],
                        "status": status,
                        "releaseNotes": [{"language": "en-US", "text": notes[:500]}],
                    }
                ],
            },
        )
        print(f"uploaded versionCode {version_code} to {track} as {status}")
        return version_code

    def set_listing(self, lang: str, title, short, full):
        edit = self.open_edit()
        # PUT replaces the whole listing, so start from what is already there:
        # uploading a description must not wipe the title (or the reverse).
        base = f"{API}/applications/{self.pkg}/edits/{edit}/listings/{lang}"
        current = self.call("GET", base)
        body = {k: current[k] for k in ("title", "shortDescription", "fullDescription",
                                        "video") if k in current}
        if title:
            body["title"] = title
        if short:
            body["shortDescription"] = short
        if full:
            body["fullDescription"] = full
        self.call("PUT", base, body)
        print(f"listing {lang} updated: {', '.join(k for k in body)}")

    def set_images(self, lang: str, image_type: str, files):
        missing = [f for f in files if not pathlib.Path(f).is_file()]
        if missing:
            sys.exit(f"missing image files: {missing}")
        edit = self.open_edit()
        base = f"{API}/applications/{self.pkg}/edits/{edit}/listings/{lang}/{image_type}"
        self.call("DELETE", base)
        for f in files:
            self.call(
                "POST",
                f"{UPLOAD}/applications/{self.pkg}/edits/{edit}/listings/{lang}/{image_type}"
                "?uploadType=media",
                raw=pathlib.Path(f).read_bytes(),
                headers={"Content-Type": "image/png"},
            )
        print(f"{len(files)} {image_type} uploaded for {lang}")

    def set_track(self, track: str, versions, status: str, notes: str = "",
                  user_fraction=None, all_countries: bool = False):
        """Point a track at an existing bundle. No upload, no listing change."""
        if all_countries and status != "inProgress":
            # Play answers `Country targeting is only supported for staged
            # releases` for a completed one, and an empty-country release is
            # rejected at commit — so targeting can only be set while staged.
            sys.exit("--all-countries requires --status inProgress")
        edit = self.open_edit()
        release = {"versionCodes": [str(v) for v in versions], "status": status}
        if all_countries:
            # Play rewrites "every country" into the full 177-code list, which
            # is why reading a track back shows both the codes and this flag.
            release["countryTargeting"] = {"countries": [], "includeRestOfWorld": True}
        if notes:
            release["releaseNotes"] = [{"language": "en-US", "text": notes[:500]}]
        if status == "inProgress":
            release["userFraction"] = user_fraction if user_fraction is not None else 0.1
        self.call(
            "PUT",
            f"{API}/applications/{self.pkg}/edits/{edit}/tracks/{track}",
            {"track": track, "releases": [release]},
        )
        print(f"track {track}: {release['versionCodes']} -> {status}")

    def status(self):
        """Print what Play actually holds. Reads only: the edit is abandoned."""
        edit = self.open_edit()
        bundles = self.call("GET", f"{API}/applications/{self.pkg}/edits/{edit}/bundles")
        got = bundles.get("bundles", [])
        print("bundles:", [(b["versionCode"], b["sha256"][:12]) for b in got] or "none")
        for t in self.call("GET", f"{API}/applications/{self.pkg}/edits/{edit}/tracks").get("tracks", []):
            rel = t.get("releases") or []
            if not rel:
                print(f"  {t['track']}: no releases")
            for r in rel:
                print(f"  {t['track']}: {r.get('versionCodes')} {r.get('status')} "
                      f"{r.get('userFraction', '-')} notes={len(r.get('releaseNotes', []))}")
        base = f"{API}/applications/{self.pkg}/edits/{edit}/listings/en-US"
        listing = self.call("GET", base)
        print(f"listing: {listing.get('title')} · "
              f"{len(listing.get('shortDescription', ''))} short · "
              f"{len(listing.get('fullDescription', ''))} full")
        for kind in ("icon", "featureGraphic", "phoneScreenshots"):
            n = len(self.call("GET", f"{base}/{kind}").get("images", []))
            print(f"  {kind}: {n}")
        self.call("DELETE", f"{API}/applications/{self.pkg}/edits/{edit}")
        self.edit = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=os.environ.get("PLAY_SA_JSON"), help="service-account JSON")
    ap.add_argument("--pkg", default="com.flutterguard.app")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, send nothing")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bundle")
    b.add_argument("--aab", required=True)
    b.add_argument("--track", default="internal")
    b.add_argument("--status", default="draft", choices=["draft", "completed", "inProgress"])
    b.add_argument("--notes-file")

    l = sub.add_parser("listing")
    l.add_argument("--lang", default="en-US")
    l.add_argument("--title")
    l.add_argument("--short")
    l.add_argument("--full-file")

    i = sub.add_parser("images")
    i.add_argument("--lang", default="en-US")
    i.add_argument("--type", default="phoneScreenshots")
    i.add_argument("--files", nargs="+", required=True)

    p = sub.add_parser("promote", help="point a track at a bundle already uploaded")
    p.add_argument("--track", default="production")
    p.add_argument("--versions", nargs="+", required=True)
    p.add_argument("--status", default="completed", choices=["draft", "completed", "inProgress"])
    p.add_argument("--fraction", type=float)
    p.add_argument("--all-countries", action="store_true")
    p.add_argument("--notes-file")

    sub.add_parser("status", help="print what Play actually holds; commits nothing")

    a = ap.parse_args()
    if not a.key:
        sys.exit("set PLAY_SA_JSON or pass --key")

    if a.dry_run:
        print(f"dry run: would run '{a.cmd}' against {a.pkg}; nothing was sent")
        return

    play = Play(a.key, a.pkg)
    if a.cmd == "bundle":
        notes = pathlib.Path(a.notes_file).read_text() if a.notes_file else ""
        play.upload_bundle(pathlib.Path(a.aab), a.track, notes, a.status)
    elif a.cmd == "listing":
        full = pathlib.Path(a.full_file).read_text() if a.full_file else None
        play.set_listing(a.lang, a.title, a.short, full)
    elif a.cmd == "promote":
        notes = pathlib.Path(a.notes_file).read_text() if a.notes_file else ""
        play.set_track(a.track, a.versions, a.status, notes, a.fraction, a.all_countries)
    elif a.cmd == "status":
        play.status()
        return
    else:
        play.set_images(a.lang, a.type, a.files)

    play.commit()
    print("committed")


if __name__ == "__main__":
    main()
