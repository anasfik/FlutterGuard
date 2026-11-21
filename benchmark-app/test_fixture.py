#!/usr/bin/env python3
"""Static regression checks for the independent FlutterGuard benchmark fixture.

This is the oracle for the *planted source facts*, not for scanner coverage.
It reads only fixture sources; it never runs an APK build or a scan.

Run: python3 benchmark-app/test_fixture.py
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ANDROID = ROOT / "android" / "app" / "src"
MANIFEST = ANDROID / "main" / "AndroidManifest.xml"
NSC = ANDROID / "main" / "res" / "xml" / "network_security_config.xml"
PACKAGE = "dev.flutterguard.benchmark_app"
ACTIVITY = "BenchmarkExportedActivity"

# Duplicated on purpose: the test is the independent oracle for what the
# fixture claims to plant. These values are synthetic and have no account.
API_KEY = "sk-proj-benchmarkFAKE4f8c2a91d7e6b350c9d1e7a2b6f80345"
DEFINE_NAME = "FG_BENCHMARK_SECRET"
DEFINE_VALUE = "fg_benchmark_define_FAKE_2b7e4c91d6a8f035"
ENV_KEY = "FG_BENCHMARK_ENV_API_KEY=fg_env_benchmark_FAKE_7c1d9e4b2a6f8035"
ENV_URL = "https://api.benchmark.invalid/v1"

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def read(path: Path) -> str:
    require(path.is_file(), f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def test_required_sources() -> None:
    for rel in (
        "pubspec.yaml",
        "lib/main.dart",
        "assets/test.env",
        "README.md",
        "android/app/build.gradle.kts",
        "android/settings.gradle.kts",
    ):
        require((ROOT / rel).is_file(), f"missing {rel}")


def test_asset_is_registered() -> None:
    pubspec = read(ROOT / "pubspec.yaml")
    for asset in ("assets/test.env", "assets/benchmark-secrets.json", "assets/benchmark-credentials.txt"):
        require(asset in pubspec, f"{asset} is not declared in pubspec")
    require("uses-material-design: true" in pubspec, "Material design not enabled")
    for forbidden in ("cupertino_icons:", "http:", "dio:", "flutter_dotenv:"):
        require(forbidden not in pubspec, f"unexpected package in pubspec: {forbidden}")


def test_dart_plants_live_values() -> None:
    dart = read(ROOT / "lib" / "main.dart")
    require(API_KEY.startswith("sk-proj-"), "synthetic key is not provider-shaped")
    require("benchmarkFAKE" in API_KEY, "synthetic key is not unmistakably fake")
    require(API_KEY in dart, "synthetic provider-shaped API key is not in main.dart")
    require(
        re.search(r"String\.fromEnvironment\(\s*'FG_BENCHMARK_SECRET'", dart),
        "dart-define is not read with String.fromEnvironment",
    )
    require(
        "rootBundle.loadString('assets/test.env')" in dart,
        "asset .env is not loaded at runtime",
    )
    # A literal only counts when it reaches the widget tree; declarations alone
    # are easy to tree-shake and prove nothing about the built artifact.
    for ident in ("benchmarkApiKey", "benchmarkDefine", "benchmarkEnvAsset", "_env"):
        require(
            len(re.findall(rf"\b{re.escape(ident)}\b", dart)) >= 2,
            f"{ident} is declared but not used on screen",
        )
    require("Text(" in dart or "SelectableText(" in dart, "no text widget displays facts")

    # Inert fixture: no network-capable import or call is allowed in Dart.
    for token in (
        "dart:io",
        "package:http",
        "HttpClient",
        "WebSocket",
        "Socket",
        "http://",
        "https://",
        "INTERNET",
    ):
        require(token not in dart, f"network-capable token in main.dart: {token}")


def test_env_asset_is_synthetic() -> None:
    env = read(ROOT / "assets" / "test.env")
    require(ENV_KEY in env, ".env synthetic API key line is missing")
    require(ENV_URL in env, ".env reserved .invalid URL is missing")
    require(".invalid" in env, ".env must use a reserved .invalid host")
    for line in env.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        require("=" in line, f"malformed .env line: {line}")
        require(
            any(marker in line for marker in ("benchmark", "BENCHMARK", "FAKE", ".invalid")),
            f".env line is not obviously synthetic: {line}",
        )


def test_permissive_network_security_config() -> None:
    nsc = read(NSC)
    tree = ET.fromstring(nsc)
    base = tree.find("base-config")
    require(base is not None, "NSC has no base-config")
    require(
        base.get("cleartextTrafficPermitted") == "true",
        "NSC does not permit cleartext traffic",
    )
    certs = {c.get("src") for c in base.iter("certificates")}
    require("user" in certs, "NSC does not trust user certificates")

    manifest = read(MANIFEST)
    require(
        'android:networkSecurityConfig="@xml/network_security_config"' in manifest,
        "manifest does not reference the permissive NSC",
    )


def test_exported_activity_and_manifest_safety() -> None:
    tree = ET.parse(MANIFEST)
    root = tree.getroot()
    app = root.find("application")
    require(app is not None, "manifest has no application element")

    activities = {
        a.get(ANDROID_NS + "name"): a for a in app.findall("activity")
    }
    activity = activities.get(f".{ACTIVITY}")
    require(activity is not None, f"{ACTIVITY} is not declared")
    require(
        activity.get(ANDROID_NS + "exported") == "true",
        f"{ACTIVITY} is not explicitly exported",
    )
    require(
        activity.get(ANDROID_NS + "permission") is None,
        f"{ACTIVITY} is protected by a permission, so the planted fact is weaker",
    )
    actions = {a.get(ANDROID_NS + "name") for a in activity.iter("action")}
    require(
        "dev.flutterguard.benchmark.EXPORTED_PROBE" in actions,
        f"{ACTIVITY} has no explicit probe action",
    )

    kotlin = read(
        ANDROID
        / "main"
        / "kotlin"
        / "dev"
        / "flutterguard"
        / "benchmark_app"
        / f"{ACTIVITY}.kt"
    )
    require(f"package {PACKAGE}" in kotlin, "probe activity package mismatch")
    require(": Activity()" in kotlin, "probe activity is not an Android Activity")

    # Project manifests declare no permissions. Merged APK manifests still
    # need a post-build check because dependencies can contribute permissions.
    for manifest in ANDROID.rglob("AndroidManifest.xml"):
        doc = ET.parse(manifest).getroot()
        for permission in doc.findall("uses-permission"):
            require(
                permission.get(ANDROID_NS + "name") != "android.permission.INTERNET",
                f"INTERNET permission in {manifest.relative_to(ROOT)}",
            )
        require(
            not doc.findall("uses-permission"),
            f"unexpected permission in {manifest.relative_to(ROOT)}",
        )


def test_hardened_manifest_plants() -> None:
    """Every high-severity artifact fact the fixture claims to plant is present."""
    tree = ET.parse(MANIFEST)
    root = tree.getroot()
    app = root.find("application")
    require(app is not None, "manifest has no application element")

    for attr, value in (
        ("debuggable", "true"),
        ("usesCleartextTraffic", "true"),
        ("allowBackup", "true"),
    ):
        require(
            app.get(ANDROID_NS + attr) == value,
            f"application android:{attr} is not {value}",
        )
    require(
        root.get(ANDROID_NS + "sharedUserId") == "dev.flutterguard.benchmark.shared",
        "sharedUserId is not declared on the manifest",
    )

    permissions = {
        p.get(ANDROID_NS + "protectionLevel") for p in root.findall("permission")
    }
    require("dangerous" in permissions, "no dangerous custom permission is declared")

    def component(tag: str, name: str) -> ET.Element:
        found = app.find(f"{tag}[@{ANDROID_NS}name='.{name}']")
        require(found is not None, f"{name} is not declared")
        return found

    for tag, name in (
        ("activity", "OAuthCallbackActivity"),
        ("service", "BenchmarkExportedService"),
        ("receiver", "BenchmarkExportedReceiver"),
        ("provider", "BenchmarkExportedProvider"),
    ):
        node = component(tag, name)
        require(
            node.get(ANDROID_NS + "exported") == "true",
            f"{name} is not explicitly exported",
        )
        require(
            node.get(ANDROID_NS + "permission") is None,
            f"{name} is permission-guarded, weakening the planted fact",
        )

    provider = component("provider", "BenchmarkExportedProvider")
    require(
        provider.get(ANDROID_NS + "grantUriPermissions") == "true",
        "provider does not grant URI permissions",
    )

    schemes = {d.get(ANDROID_NS + "scheme") for d in app.iter("data")}
    require("benchmark-oauth" in schemes, "OAuth-shaped deep link scheme is missing")


def test_exported_component_classes() -> None:
    directory = (
        ANDROID / "main" / "kotlin" / "dev" / "flutterguard" / "benchmark_app"
    )
    for name, supertype in (
        ("OAuthCallbackActivity", ": Activity()"),
        ("BenchmarkExportedService", ": Service()"),
        ("BenchmarkExportedReceiver", ": BroadcastReceiver()"),
        ("BenchmarkExportedProvider", ": ContentProvider()"),
    ):
        source = read(directory / f"{name}.kt")
        require(f"package {PACKAGE}" in source, f"{name} package mismatch")
        require(supertype in source, f"{name} is not an Android {supertype.split()[1]}")


def test_planted_secrets_are_synthetic() -> None:
    """The hardened assets must carry recognisable fake markers, never plausible keys."""
    for name in ("benchmark-secrets.json", "benchmark-credentials.txt"):
        text = read(ROOT / "assets" / name)
        require(".invalid" in text or "FAKE" in text or "BENCHMARK" in text, f"{name} has no synthetic markers")
        for line in text.splitlines():
            if not line.strip() or line.strip().startswith(("#", "//", '"', "{", "}")):
                continue
            if any(marker in line for marker in ("AKIA", "ghp_", "AIza", "AccountKey", "PREFIX", "PRIVATE KEY")):
                require(
                    any(marker in line for marker in ("FAKE", "BENCHMARK", "benchmark")),
                    f"plausible credential line in {name}: {line.strip()[:40]}",
                )
    documents = "\n".join(
        read(ROOT / "assets" / name) for name in ("benchmark-secrets.json", "benchmark-credentials.txt")
    )
    for expected in (
        "sk_live_",
        "ghp_",
        "glpat-",
        "dckr_pat_",
        "sb_secret_",
        "AIza",
        "AKIA",
        "AccountKey=",
        '"type": "service_account"',
        "sk-ant-",
        "SG.",
        "ey",
        "postgres://",
        "-----BEGIN RSA PRIVATE KEY-----",
    ):
        require(expected in documents, f"planted asset is missing {expected}")


def test_no_signing_material() -> None:
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        require(path.suffix not in {".jks", ".keystore"}, f"signing file in fixture: {path}")
        require(path.name != "key.properties", f"signing properties in fixture: {path}")
    gradle = read(ROOT / "android" / "app" / "build.gradle.kts")
    for token in ("storeFile", "storePassword", "keyPassword"):
        require(token not in gradle, f"custom signer configured in release build: {token}")


def test_build_recipe_is_explicit() -> None:
    readme = read(ROOT / "README.md")
    for token in (
        "flutter pub get --offline",
        "flutter build apk --debug",
        "flutter build apk --release",
        "--obfuscate",
        "--split-debug-info",
        f"--dart-define={DEFINE_NAME}={DEFINE_VALUE}",
        "dist/benchmark-debug.apk",
        "dist/benchmark-plain-release.apk",
        "dist/benchmark-obfuscated-release.apk",
        "flutter clean",
        "no network",
        "not a real credential",
    ):
        require(token in readme, f"build recipe/README missing: {token}")
    commands = re.findall(r"^flutter build apk .*?(?=\n\S|\n\n|\Z)", readme, re.M | re.S)
    require(len(commands) == 3, "recipe must configure three Flutter variants")
    for command in commands:
        require("--config-only" in command, "Flutter must configure without running Gradle")
        require(
            f"--dart-define={DEFINE_NAME}={DEFINE_VALUE}" in command,
            "every variant must carry the synthetic define",
        )
    require("--obfuscate" in commands[2] and "--split-debug-info=dist/" in commands[2],
            "obfuscation maps must survive flutter clean")
    gradle_commands = re.findall(r"^\(cd android && \./gradlew .*$", readme, re.M)
    require(len(gradle_commands) == 3, "every variant needs an explicit Gradle build")
    require(all("--offline" in command for command in gradle_commands),
            "each Gradle build must enforce offline resolution")
    payloads = re.findall(r"DEFINES=\$\(printf %s '([^']+)'", readme)
    require(payloads == [f"{DEFINE_NAME}={DEFINE_VALUE}"] * 3,
            "each variant must define the exact effective Gradle payload")
    for command in gradle_commands:
        require('-Pdart-defines="$DEFINES"' in command,
                "each Gradle build must pass the synthetic define")
    require('-Psplit-debug-info="$PWD/../dist/obfuscation-symbols"' in gradle_commands[2],
            "obfuscated Gradle build must preserve maps in dist")
    require(all("-Ptrack-widget-creation=false" in command for command in gradle_commands[1:]),
            "release Gradle properties must match Flutter release defaults")


def test_no_obvious_real_credentials() -> None:
    synthetic_assets = {
        ROOT / "assets" / "benchmark-secrets.json",
        ROOT / "assets" / "benchmark-credentials.txt",
    }
    forbidden = (
        "AKIA",
        "ghp_",
        "github_pat_",
        "AIza",
        "xoxb-",
        "-----BEGIN",
        "PRIVATE KEY",
    )
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == Path(__file__) or path in synthetic_assets:
            continue
        if any(part in {"build", ".dart_tool", ".gradle", "dist", "__pycache__"} for part in path.parts):
            continue
        if path.suffix in {".png", ".jar", ".lock", ".pyc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for token in forbidden:
            require(token not in text, f"possible real credential marker {token} in {path.name}")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"ok {test.__name__}")
    print(f"PASS: {len(tests)} fixture checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
