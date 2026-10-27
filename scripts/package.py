#!/usr/bin/env python3
"""Build native Debian packages or a macOS app/DMG with optional BPF setup.

Python 3.11+. Builds locally; never installs packages, changes host permissions,
uploads artifacts, or notarizes automatically. Use --check on any platform.
"""
import argparse
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"


def run(*args, cwd=None):
    print("Running:", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd or ROOT, check=True)


def copy(source, target, mode=0o644):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def check():
    icon = ROOT / "assets/icons/portspecter-macos.png"
    if icon.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("macOS app icon is missing or is not a PNG")
    scripts = [PACKAGING / "linux/portspecter-packet-access"]
    scripts += [PACKAGING / "macos" / name for name in ("packet-access", "preinstall", "postinstall")]
    for script in scripts:
        data = script.read_bytes()
        if b"\r" in data or not data.startswith(b"#!/bin/sh\n"):
            raise ValueError(f"Expected LF-terminated POSIX shell script: {script}")
        if shutil.which("sh"):
            run("sh", "-n", script)
    with (PACKAGING / "macos/org.portspecter.packet-access.plist").open("rb") as stream:
        daemon = plistlib.load(stream)
    assert daemon["Label"] == "org.portspecter.packet-access"
    assert daemon["ProgramArguments"] == ["/Library/Application Support/PortSpecter/PacketAccess/packet-access", "apply"]
    assert daemon["RunAtLoad"] and daemon["StartInterval"] == 30
    assert "Exec=portspecter\n" in (PACKAGING / "linux/portspecter.desktop").read_text()
    print("Packaging sources validated; native installation/runtime testing is separate.")


def linux(binary, version, output, work):
    arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
    stage = work / "deb"
    copy(binary, stage / "usr/bin/portspecter", 0o755)
    copy(PACKAGING / "linux/portspecter-packet-access", stage / "usr/sbin/portspecter-packet-access", 0o755)
    copy(PACKAGING / "linux/portspecter.desktop", stage / "usr/share/applications/portspecter.desktop")
    for name in ("LICENSE", "NOTICE", "README.md"):
        copy(ROOT / name, stage / "usr/share/doc/portspecter" / name)
    # Direct ELF dependencies are measured on the build host. dlopen dependencies
    # (libpcap, window backends and graphics) also need explicit package entries.
    control = """Source: portspecter
Section: net
Priority: optional
Maintainer: PortSpecter Maintainers <maintainers@portspecter.invalid>

Package: portspecter
Architecture: any
Description: Native network discovery and port scanner
"""
    (work / "debian").mkdir()
    (work / "debian/control").write_text(control, encoding="utf-8")
    dependencies = subprocess.check_output(
        ["dpkg-shlibdeps", "-O", "-e" + str(stage / "usr/bin/portspecter")],
        cwd=work, text=True,
    )
    direct = next(line.split("=", 1)[1] for line in dependencies.splitlines() if line.startswith("shlibs:Depends="))
    extra = "ca-certificates, smbclient, libpcap0.8t64 | libpcap0.8, libcap2-bin, iproute2, iputils-ping, libxkbcommon0, libwayland-client0, libx11-6, libxcursor1, libxi6, libxrandr2, libgl1, libfontconfig1, libdbus-1-3"
    metadata = stage / "DEBIAN"
    metadata.mkdir()
    (metadata / "control").write_text(
        f"Package: portspecter\nVersion: {version}\nArchitecture: {arch}\nSection: net\nPriority: optional\n"
        f"Maintainer: PortSpecter Maintainers <maintainers@portspecter.invalid>\nDepends: {direct}, {extra}\n"
        "Description: Native network discovery and port scanner\n TCP, UDP and optional native IPv4 SYN scanning.\n",
        encoding="utf-8",
    )
    package = output / f"portspecter_{version}_{arch}.deb"
    run("dpkg-deb", "--root-owner-group", "--build", stage, package)
    run("dpkg-deb", "--info", package)
    run("dpkg-deb", "--contents", package)
    print("SYN is opt-in after installation: sudo portspecter-packet-access enable")


def macos(binary, version, output, work):
    arch = platform.machine()
    content = work / "image"
    app = content / "PortSpecter.app"
    copy(binary, app / "Contents/MacOS/portspecter", 0o755)
    info = {
        "CFBundleIdentifier": "org.portspecter.desktop",
        "CFBundleName": "PortSpecter", "CFBundleDisplayName": "PortSpecter",
        "CFBundleExecutable": "portspecter", "CFBundlePackageType": "APPL",
        "CFBundleIconFile": "PortSpecter.icns",
        "CFBundleShortVersionString": version, "CFBundleVersion": version,
        "LSMinimumSystemVersion": "14.0", "NSHighResolutionCapable": True,
    }
    with (app / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    for name in ("LICENSE", "NOTICE"):
        copy(ROOT / name, app / "Contents/Resources" / name)
    iconset = work / "PortSpecter.iconset"
    iconset.mkdir()
    master = ROOT / "assets/icons/portspecter-macos.png"
    for size in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            pixels = size * scale
            suffix = "@2x" if scale == 2 else ""
            run("sips", "-z", pixels, pixels, master, "--out", iconset / f"icon_{size}x{size}{suffix}.png")
    run("iconutil", "--convert", "icns", "--output", app / "Contents/Resources/PortSpecter.icns", iconset)
    identity = os.environ.get("PORTSPECTER_SIGN_IDENTITY")
    if identity:
        run("codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identity, app)
    else:
        run("codesign", "--force", "--sign", "-", app)
        print("Development build: ad-hoc signed, NOT notarized. Public release requires Developer ID and notarization.")
    run("codesign", "--verify", "--strict", "--verbose=2", app)
    payload = work / "packet-root"
    helper = payload / "Library/Application Support/PortSpecter/PacketAccess/packet-access"
    copy(PACKAGING / "macos/packet-access", helper, 0o755)
    copy(PACKAGING / "macos/org.portspecter.packet-access.plist", payload / "Library/LaunchDaemons/org.portspecter.packet-access.plist")
    scripts = work / "installer-scripts"
    for name in ("preinstall", "postinstall"):
        copy(PACKAGING / "macos" / name, scripts / name, 0o755)
    package = content / "Optional SYN Packet Access.pkg"
    args = ["pkgbuild", "--root", payload, "--scripts", scripts,
            "--identifier", "org.portspecter.packet-access", "--version", version,
            "--install-location", "/", "--ownership", "recommended"]
    installer_identity = os.environ.get("PORTSPECTER_INSTALLER_IDENTITY")
    if installer_identity:
        args += ["--sign", installer_identity]
    run(*args, package)
    os.symlink("/Applications", content / "Applications")
    (content / "Read me first.txt").write_text(
        "PortSpecter\n\nDrag PortSpecter.app to Applications. TCP connect and UDP need no BPF setup.\n\n"
        "OPTIONAL: For SYN, open Optional SYN Packet Access.pkg and authorize the administrator prompt.\n"
        "This grants the currently logged-in desktop user membership in the shared access_bpf group.\n"
        "It installs a root launch daemon to grant that group read/write access to /dev/bpf* at boot and every 30 seconds.\n"
        "This is packet capture/injection access for that user, not a permission limited to this application.\n"
        "Log out and back in after installation. Launch PortSpecter normally, without sudo.\n\n"
        "Remove the optional access setup using Terminal:\n"
        "sudo '/Library/Application Support/PortSpecter/PacketAccess/packet-access' remove\n"
        "Only memberships added by this installer are removed; pre-existing/shared access is retained.\n\n"
        "Native SYN is experimental and IPv4-only. Unsupported raw VPN links report an error.\n"
        "Unsigned/ad-hoc development packages are not a notarized public release.\n",
        encoding="utf-8",
    )
    dmg = output / f"PortSpecter-{version}-macos-{arch}.dmg"
    run("hdiutil", "create", "-ov", "-format", "UDZO", "-volname", "PortSpecter", "-srcfolder", content, dmg)
    run("hdiutil", "verify", dmg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate packaging sources without building/installing")
    parser.add_argument("--binary", type=Path, help="Use an already compiled native binary (CI smoke builds)")
    args = parser.parse_args()
    check()
    if args.check:
        return
    system = platform.system()
    if system not in ("Linux", "Darwin"):
        parser.error("Run this script on Linux or macOS to produce that platform's native package")
    with (ROOT / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["workspace"]["package"]["version"]
    binary = args.binary.resolve() if args.binary else ROOT / "target/release/portspecter"
    if not args.binary:
        run("cargo", "build", "--release", "--locked", "-p", "portspecter-desktop")
    if not binary.is_file():
        parser.error(f"Native binary not found: {binary}")
    output = ROOT / "artifacts/packages"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="portspecter-package-") as directory:
        build = linux if system == "Linux" else macos
        build(binary, version, output, Path(directory))
    print("Package output:", output)


if __name__ == "__main__":
    main()
