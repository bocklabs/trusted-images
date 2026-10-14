import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("config_binding", Path(__file__).resolve().parents[1] / "scripts/native_chisel_inventory.py")
if SPEC is None or SPEC.loader is None:
    raise ImportError("Cannot load native config binding")
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativeConfigBindingTests(unittest.TestCase):
    def test_docker_config_projection_keeps_runtime_and_digest_binding(self):
        config: dict = {"architecture": "amd64", "rootfs": {"diff_ids": []}, "container_config": {"Cmd": ["/bin/sh"]},
                  "config": {"Cmd": ["/bin/sh"], "User": "101", "Env": ["A=B"], "Entrypoint": ["/app"],
                             "ArgsEscaped": True, "AttachStdin": False, "Volumes": None, "OnBuild": [],
                             "Labels": {"empty-value": ""}}}
        reported = copy.deepcopy(config)
        del reported["container_config"]
        for key in ("AttachStdin", "Volumes", "OnBuild"):
            del reported["config"][key]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.json").write_text(json.dumps(config))
            config_bytes = (root / "config.json").read_bytes()
            config_id = "sha256:" + native.digest(config_bytes)
            (root / "manifest.json").write_text(json.dumps({"config": {"digest": config_id}, "layers": []}))
            reference = "example.test/image@sha256:" + native.file_digest(root / "manifest.json")
            raw: dict = {"ArtifactType": "container_image", "ArtifactName": reference,
                   "Metadata": {"ImageID": config_id, "ImageConfig": reported, "DiffIDs": []}}
            inputs = {"manifest": root / "manifest.json", "config": root / "config.json", "reference": reference, "layers": []}
            self.assertEqual(native.image_files(inputs, raw), {})
            for key, value in (("Cmd", ["/changed"]), ("User", "0"), ("AttachStdin", 0), ("unknown", "")):
                changed = copy.deepcopy(raw)
                changed["Metadata"]["ImageConfig"]["config"][key] = value
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "config mismatch"):
                    native.image_files(inputs, changed)
            raw["Metadata"]["ImageID"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(ValueError, "config mismatch"):
                native.image_files(inputs, raw)
