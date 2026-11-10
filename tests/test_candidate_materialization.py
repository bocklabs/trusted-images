import copy
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests.workflow_helpers import load_workflow

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from finalize_candidate_config import finalize
from validate_image import config_drift, label_drift
from verify_candidate_archive import verify


class CandidateMaterializationTests(unittest.TestCase):
    def test_loaded_image_is_bound_to_expected_config_even_when_id_is_manifest(self) -> None:
        workflow = load_workflow(Path(__file__).parents[1] / ".github/workflows/promote-candidate.yaml")
        run = next(step["run"] for step in workflow["jobs"]["validate"]["steps"] if step.get("id") == "patched")
        start = run.index('FINAL_IMAGE_ID=')
        end = run.index("docker image inspect copa:final --format '{{json .Config.Labels}}'", start)
        snippet = run[start:end]
        image_id = "sha256:" + "a" * 64
        content = b'{"architecture":"amd64","config":{"Labels":{"test":"keep"}}}'
        digest = hashlib.sha256(content).hexdigest()
        self.assertNotEqual(image_id, "sha256:" + digest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").symlink_to(Path(__file__).parents[1] / "scripts", target_is_directory=True)
            (root / "candidate-manifest.json").write_text(json.dumps({"config": {"digest": "sha256:" + digest, "size": len(content)}}))
            docker = root / "docker"
            docker.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    print(os.environ["TEST_IMAGE_ID"])
elif args == ["image", "save", os.environ["TEST_IMAGE_ID"]]:
    sys.stdout.buffer.write(pathlib.Path(os.environ["TEST_IMAGE_ARCHIVE"]).read_bytes())
    sys.stdout.buffer.write(b"\\0" * 1000000)
else:
    sys.exit(2)
''')
            docker.chmod(0o755)
            env = os.environ | {"PATH": str(root) + os.pathsep + os.environ["PATH"], "TEST_IMAGE_ID": image_id,
                                "TEST_IMAGE_ARCHIVE": str(root / "saved.tar")}
            config_path = "blobs/sha256/" + digest
            legacy_path = digest + ".json"
            for name, filename, raw, selected, expected in (
                ("containerd", config_path, content, config_path, 0),
                ("classic", legacy_path, content, legacy_path, 0),
                ("changed", config_path, content[:-1] + b"!", config_path, 1),
                ("unreferenced", config_path, content, "blobs/sha256/" + "b" * 64, 1),
                ("malformed", config_path, content, [], 1),
            ):
                with self.subTest(name=name):
                    with tarfile.open(root / "saved.tar", "w") as archive:
                        for path, data in ((filename, raw), ("manifest.json", json.dumps([{"Config": selected}]).encode())):
                            entry = tarfile.TarInfo(path)
                            entry.size = len(data)
                            archive.addfile(entry, io.BytesIO(data))
                    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", snippet], cwd=root, env=env,
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode == 0, expected == 0, result.stdout + result.stderr)
                    self.assertNotIn("BrokenPipe", result.stderr)
                    if name == "malformed":
                        self.assertIn("selected archive config digest mismatch", result.stderr)

    def test_drain_error_preserves_verification_error_and_fails_after_success(self) -> None:
        content = b'{}'
        digest = hashlib.sha256(content).hexdigest()
        config_path = "blobs/sha256/" + digest

        class FailOnEof(io.BytesIO):
            def __init__(self, data: bytes, error_type: type[OSError | ValueError]) -> None:
                super().__init__(data)
                self.error_type = error_type

            def read(self, size: int | None = -1) -> bytes:
                if self.tell() == len(self.getbuffer()):
                    raise self.error_type("readback stream failed")
                return super().read(size)

        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "candidate-manifest.json"
            manifest.write_text(json.dumps({"config": {"digest": "sha256:" + digest, "size": len(content)}}))
            for selected, drain_error, error_type, message in (
                ("wrong.json", OSError, ValueError, "selected archive config digest mismatch"),
                (config_path, OSError, OSError, "readback stream failed"),
                ("wrong.json", ValueError, ValueError, "selected archive config digest mismatch"),
                (config_path, ValueError, ValueError, "readback stream failed"),
            ):
                with self.subTest(selected=selected, drain_error=drain_error.__name__):
                    data = io.BytesIO()
                    with tarfile.open(fileobj=data, mode="w") as archive:
                        for name, raw in ((config_path, content), ("manifest.json", json.dumps([{"Config": selected}]).encode())):
                            member = tarfile.TarInfo(name)
                            member.size = len(raw)
                            archive.addfile(member, io.BytesIO(raw))
                    stream = FailOnEof(data.getvalue(), drain_error)
                    try:
                        raise RuntimeError("outer error")
                    except RuntimeError:
                        with self.assertRaisesRegex(error_type, message) as caught:
                            verify(manifest, stream)
                    if selected == "wrong.json":
                        self.assertIn("readback stream failed", " ".join(caught.exception.__notes__))

    def test_finalizer_preserves_healthcheck_removes_new_labels_and_rebinds_descriptors(self) -> None:
        original: dict = {"Labels": {"sh.copa.chisel.version": "original"}}
        candidate: dict = {"architecture": "amd64", "config": {"Labels": {
            "sh.copa.chisel.version": "changed", "sh.copa.chisel.release": "ubuntu-24.04",
            "unknown.extra": "keep"}}, "rootfs": {"diff_ids": ["sha256:" + "a" * 64]}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blobs = root / "blobs/sha256"
            blobs.mkdir(parents=True)
            def put(value: dict, media_type: str) -> dict:
                raw = json.dumps(value).encode()
                digest = hashlib.sha256(raw).hexdigest()
                (blobs / digest).write_bytes(raw)
                return {"digest": "sha256:" + digest, "size": len(raw), "mediaType": media_type}
            manifest: dict = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": put(candidate, "application/vnd.oci.image.config.v1+json"),
                        "layers": [{"digest": "sha256:" + "a" * 64, "size": 123}]}
            index = {"schemaVersion": 2, "manifests": [put(manifest, manifest["mediaType"])]}
            (root / "index.json").write_text(json.dumps(index))
            baseline = root / "original.json"
            baseline.write_text(json.dumps({"config": original}))
            finalize(root, baseline)
            descriptor = json.loads((root / "index.json").read_bytes())["manifests"][0]
            final_manifest_raw = (blobs / descriptor["digest"][7:]).read_bytes()
            self.assertEqual((len(final_manifest_raw), "sha256:" + hashlib.sha256(final_manifest_raw).hexdigest()),
                             (descriptor["size"], descriptor["digest"]))
            final_manifest = json.loads(final_manifest_raw)
            config_descriptor = final_manifest["config"]
            final_config_raw = (blobs / config_descriptor["digest"][7:]).read_bytes()
            self.assertEqual((len(final_config_raw), "sha256:" + hashlib.sha256(final_config_raw).hexdigest()),
                             (config_descriptor["size"], config_descriptor["digest"]))
            expected = copy.deepcopy(candidate)
            del expected["config"]["Labels"]["sh.copa.chisel.release"]
            self.assertEqual(json.loads(final_config_raw), expected)
            self.assertEqual(final_manifest["layers"], manifest["layers"])
            drift = label_drift(original, expected["config"], "", "")
            self.assertTrue(any("sh.copa.chisel.version" in item for item in drift))
            self.assertTrue(any("unknown.extra" in item for item in drift))
            unchanged = {path.name: path.read_bytes() for path in blobs.iterdir()}
            index_bytes = (root / "index.json").read_bytes()
            finalize(root, baseline)
            self.assertEqual((root / "index.json").read_bytes(), index_bytes)
            self.assertEqual({path.name: path.read_bytes() for path in blobs.iterdir()}, unchanged)
            healthcheck = {"Test": ["CMD-SHELL", "wget --no-verbose --tries=1 --spider -Y off http://127.0.0.1:$PORT/api/healthcheck || exit 1"],
                           "Interval": 10000000000, "Timeout": 3000000000, "StartPeriod": 20000000000}
            original["Healthcheck"] = healthcheck
            baseline.write_text(json.dumps({"config": original}))
            for present in (False, True):
                with self.subTest(changed_healthcheck=present):
                    candidate_config = copy.deepcopy(expected)
                    if present:
                        candidate_config["config"]["Healthcheck"] = {"Test": ["NONE"]}
                    manifest["config"] = put(candidate_config, "application/vnd.oci.image.config.v1+json")
                    index["manifests"] = [put(manifest, manifest["mediaType"])]
                    (root / "index.json").write_text(json.dumps(index))
                    finalize(root, baseline)
                    descriptor = json.loads((root / "index.json").read_bytes())["manifests"][0]
                    raw_manifest = (blobs / descriptor["digest"][7:]).read_bytes()
                    self.assertEqual((len(raw_manifest), "sha256:" + hashlib.sha256(raw_manifest).hexdigest()),
                                     (descriptor["size"], descriptor["digest"]))
                    config_descriptor = json.loads(raw_manifest)["config"]
                    raw_config = (blobs / config_descriptor["digest"][7:]).read_bytes()
                    self.assertEqual((len(raw_config), "sha256:" + hashlib.sha256(raw_config).hexdigest()),
                                     (config_descriptor["size"], config_descriptor["digest"]))
                    restored = json.loads(raw_config)
                    if not present:
                        candidate_config["config"]["Healthcheck"] = healthcheck
                    self.assertEqual(restored, candidate_config)
                    health_drift = [item for item in config_drift(original, restored["config"])
                                    if "Healthcheck" in item]
                    self.assertEqual(bool(health_drift), present)
            (root / "index.json").write_bytes(index_bytes)
            broken = json.loads(index_bytes)
            broken["manifests"][0]["size"] += 1
            (root / "index.json").write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, "digest or size mismatch"):
                finalize(root, baseline)
            broken["manifests"].append(broken["manifests"][0])
            (root / "index.json").write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, "one image manifest"):
                finalize(root, baseline)

    def test_scan_and_runtime_archive_are_materialized_from_final_oci(self) -> None:
        workflow = load_workflow(Path(__file__).parents[1] / ".github/workflows/promote-candidate.yaml")
        steps = workflow["jobs"]["validate"]["steps"]
        run = next(step["run"] for step in steps if step.get("id") == "patched")
        self.assertLess(run.index("python3 scripts/finalize_candidate_config.py candidate-oci child-config.json"),
                        run.index("CANDIDATE_MANIFEST_DIGEST="))
        command = next(line.strip() for line in run.replace("\\\n", "").splitlines()
                       if "copy --format v2s2 oci:" in line)
        self.assertEqual(shlex.split(command)[-2:], ["oci:/workspace/candidate-oci:candidate",
                                                   "docker-archive:/workspace/candidate-final.tar:copa:final"])
        ordered = [run.index(token) for token in ("rm candidate-final.tar", "copy --format v2s2 oci:",
                   "python3 scripts/verify_candidate_archive.py candidate-manifest.json candidate-final.tar",
                   "docker load --input candidate-final.tar", "FINAL_IMAGE_ID=",
                   'docker image save "${FINAL_IMAGE_ID}" | python3 scripts/verify_candidate_archive.py candidate-manifest.json -',
                   'echo "image_id=${FINAL_IMAGE_ID}"')]
        self.assertEqual(ordered, sorted(ordered))
        scan = next(step for step in steps if step.get("id") == "scanafter")
        self.assertEqual(scan["with"]["input"], "candidate-final.tar")
