# SPDX-FileCopyrightText: 2026 Blender Authors
#
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest


IOS_DIR = Path(__file__).resolve().parents[1]
AUDITOR = IOS_DIR / "audit.py"
PINNED_DONOR_SHA = "a1de44dd54af75a4c8c4a29a5fed2a1334a87446"


class AuditorTestCase(unittest.TestCase):
    def run_audit(self, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, os.fspath(AUDITOR), *(os.fspath(arg) for arg in arguments)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_audit_fails(self, result: subprocess.CompletedProcess[str], code: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertIn(code, {finding["code"] for finding in report["findings"]})


class ManifestAuditTests(AuditorTestCase):
    def test_rejects_malformed_run_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "request.json"
            manifest.write_text('{"packet": 10, "target": "ios-simulator-arm64"}\n')
            self.assert_audit_fails(self.run_audit("manifest", manifest), "MANIFEST-SCHEMA")

    def test_accepts_complete_run_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "request.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_id": "20260810T010203Z-fbe6228777e7-ios-sim-minimal",
                        "packet": "N020",
                        "baseline_sha": "fbe6228777e7d9afefcd61a413844e790ae75db7",
                        "donor_sha": "a1de44dd54af75a4c8c4a29a5fed2a1334a87446",
                        "target": "ios-simulator-arm64",
                        "feature_profile": "ios_sim_minimal",
                        "signing_mode": "SIMULATOR_LOCAL",
                        "paths": {
                            "source": "/Users/example/Blender-ios-5.2",
                            "bulk": "/Volumes/BlenderBuild/blender-ios",
                            "artifact": "/Volumes/BlenderBuild/blender-ios/artifacts/example",
                        },
                    }
                )
                + "\n"
            )
            result = self.run_audit("manifest", manifest)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class PathAuditTests(AuditorTestCase):
    def test_rejects_private_absolute_paths_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "cache.txt"
            document.write_text("compiler=/Users/alice/Library/Developer/tool\n")
            self.assert_audit_fails(self.run_audit("paths", document), "PATH-PRIVATE")

    def test_allows_canonical_volume_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "cache.txt"
            document.write_text("build=/Volumes/BlenderBuild/blender-ios/build/example\n")
            result = self.run_audit("paths", document)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_allows_upstream_examples_in_distribution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "vendor-1.0.dist-info" / "METADATA"
            metadata.parent.mkdir()
            metadata.write_text("Example output: /Users/upstream/Documents\n")
            result = self.run_audit("paths", Path(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class BundleAuditTests(AuditorTestCase):
    @staticmethod
    def write_info(bundle: Path, executable: str = "Blender") -> None:
        with (bundle / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": "org.blender.Blender",
                    "CFBundleName": "Blender",
                    "CFBundleExecutable": executable,
                    "CFBundlePackageType": "APPL",
                },
                handle,
            )

    def test_rejects_missing_plist_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Blender.app"
            bundle.mkdir()
            self.assert_audit_fails(
                self.run_audit("bundle", bundle, "--required-resource", "startup.blend"),
                "BUNDLE-PLIST-MISSING",
            )

    def test_rejects_unsigned_lane_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Blender.app"
            bundle.mkdir()
            self.write_info(bundle)
            (bundle / "Blender").write_bytes(b"fixture")
            (bundle / "startup.blend").write_bytes(b"fixture")
            (bundle / "embedded.mobileprovision").write_text("fixture")
            (bundle / "_CodeSignature").mkdir()
            result = self.run_audit(
                "bundle",
                bundle,
                "--lane",
                "device-unsigned",
                "--required-resource",
                "startup.blend",
            )
            self.assert_audit_fails(result, "SIGN-CONTAMINATION")

    def test_accepts_minimal_unsigned_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Blender.app"
            bundle.mkdir()
            self.write_info(bundle)
            (bundle / "Blender").write_bytes(b"fixture")
            (bundle / "startup.blend").write_bytes(b"fixture")
            result = self.run_audit(
                "bundle",
                bundle,
                "--lane",
                "device-unsigned",
                "--required-resource",
                "startup.blend",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class AbiAuditTests(AuditorTestCase):
    def compile_object(self, sdk: str, output: Path, simulator: bool = False) -> None:
        source = output.with_suffix(".c")
        source.write_text("int blender_ios_fixture(void) { return 0; }\n")
        command = ["xcrun", "--sdk", sdk, "clang", "-arch", "arm64"]
        if simulator:
            command.extend(["-target", "arm64-apple-ios13.0-simulator"])
        command.extend(["-c", os.fspath(source), "-o", os.fspath(output)])
        subprocess.run(command, check=True, capture_output=True, text=True)

    def test_rejects_macos_object_for_simulator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "host.o"
            self.compile_object("macosx", binary)
            self.assert_audit_fails(
                self.run_audit("abi", binary, "--target", "ios-simulator", "--arch", "arm64"),
                "ABI-PLATFORM",
            )

    def test_accepts_arm64_simulator_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "simulator.o"
            self.compile_object("iphonesimulator", binary, simulator=True)
            result = self.run_audit(
                "abi", binary, "--target", "ios-simulator", "--arch", "arm64"
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_accepts_arm64_simulator_static_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "simulator.o"
            archive = root / "libfixture.a"
            self.compile_object("iphonesimulator", binary, simulator=True)
            subprocess.run(
                ["xcrun", "ar", "rcs", os.fspath(archive), os.fspath(binary)],
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.run_audit(
                "abi", archive, "--target", "ios-simulator", "--arch", "arm64"
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class MinimumOsAuditTests(AuditorTestCase):
    @staticmethod
    def macho(minos: str, legacy: bool = False) -> bytes:
        major, minor = (int(part) for part in minos.split("."))
        encoded = (major << 16) | (minor << 8)
        if legacy:
            command = struct.pack("<4I", 0x25, 16, encoded, encoded)
        else:
            command = struct.pack("<6I", 0x32, 24, 2, encoded, encoded, 0)
        header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
        return header + command

    def write_bundle(self, root: Path, minos: str, plist_minos: str) -> Path:
        bundle = root / "Blender.app"
        framework = bundle / "Frameworks" / "Fixture.framework"
        framework.mkdir(parents=True)
        (bundle / "Blender").write_bytes(self.macho(minos))
        (framework / "Fixture").write_bytes(self.macho("16.0", legacy=True))
        (bundle / "Info.plist").write_bytes(plistlib.dumps({"MinimumOSVersion": plist_minos}))
        (bundle / "notes.txt").write_text("not a binary\n")
        return bundle

    def test_rejects_binary_built_for_newer_ios_than_supported(self) -> None:
        # Reproduces the iOS 16.2 launch crash: dyld refuses a binary "built for iOS 18.0".
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.write_bundle(Path(directory), "18.0", "16.2")
            self.assert_audit_fails(
                self.run_audit("minos", bundle, "--maximum", "16.2"), "MINOS-MACHO"
            )

    def test_rejects_plist_minimum_newer_than_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.write_bundle(Path(directory), "16.2", "18.0")
            self.assert_audit_fails(
                self.run_audit("minos", bundle, "--maximum", "16.2"), "MINOS-PLIST"
            )

    def test_accepts_bundle_targeting_supported_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.write_bundle(Path(directory), "16.2", "16.2")
            result = self.run_audit("minos", bundle, "--maximum", "16.2")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reads_every_slice_of_a_universal_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Blender.app"
            bundle.mkdir()
            first = self.macho("16.2")
            second = self.macho("18.0")
            header = struct.pack(">2I", 0xCAFEBABE, 2)
            offset = 4096
            entries = struct.pack(">5I", 0x0100000C, 0, offset, len(first), 12)
            entries += struct.pack(">5I", 0x0100000C, 1, offset * 2, len(second), 12)
            data = bytearray(offset * 2 + len(second))
            data[: len(header) + len(entries)] = header + entries
            data[offset : offset + len(first)] = first
            data[offset * 2 :] = second
            (bundle / "Blender").write_bytes(bytes(data))
            self.assert_audit_fails(
                self.run_audit("minos", bundle, "--maximum", "16.2"), "MINOS-MACHO"
            )


class PortMapAuditTests(AuditorTestCase):
    def test_port_map_matches_exact_donor_delta(self) -> None:
        port_map = IOS_DIR.parents[1] / "docs" / "ios" / "PORT_MAP.tsv"
        result = self.run_audit(
            "port-map",
            port_map,
            "--repository",
            IOS_DIR.parents[1],
            "--base",
            "v5.1.2",
            "--donor",
            PINNED_DONOR_SHA,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SigningProbeContractTests(unittest.TestCase):
    def test_probe_contains_no_identity_or_profile_inputs(self) -> None:
        probe_directory = IOS_DIR / "signing_probe"
        sources = [
            probe_directory / "CMakeLists.txt",
            probe_directory / "Info.plist.in",
            probe_directory / "main.m",
        ]
        combined = "\n".join(source.read_text() for source in sources)
        for forbidden in (
            "security find-identity",
            "DEVELOPMENT_TEAM",
            "PROVISIONING_PROFILE",
            "CODE_SIGN_IDENTITY",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
