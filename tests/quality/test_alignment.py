"""防止需求遗漏、虚报验收和 API／页面清单偏移进入发布流程。"""
import copy
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_alignment as alignment


class AlignmentTests(unittest.TestCase):
    def setUp(self):
        self.registry = alignment.load(ROOT, "tests/acceptance/requirements.json")
        self.inventory = alignment.load(ROOT, "tests/acceptance/implementation.json")

    def test_missing_duplicate_and_invented_acceptance_rejected(self):
        for mutate in (lambda data: data["requirements"].pop(),
                       lambda data: data["requirements"].append(copy.deepcopy(data["requirements"][0])),
                       lambda data: data["requirements"][0].update(acceptance="passed"),
                       lambda data: data["requirements"][0].update(state="implemented"),
                       lambda data: data["requirements"][0].update(capabilities=["invented"])):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                inventory = copy.deepcopy(self.inventory)
                mutate(inventory)
                alignment.validate_inventory(ROOT, self.registry, inventory)

    def test_code_references_require_existing_contained_files(self):
        for value in ("internal/missing.go", "../external.go", "/etc/passwd", "internal//model/model.go"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inventory = copy.deepcopy(self.inventory)
                inventory["capabilities"][0]["code"] = [value]
                alignment.validate_inventory(ROOT, self.registry, inventory)

    def test_undocumented_and_unregistered_api_operations_rejected(self):
        actual = alignment.load(ROOT, "api/openapi/platform.json")
        for mutate in (lambda doc: doc["paths"].pop("/api/v1/models/providers"),
                       lambda doc: doc["paths"].update({"/api/v1/not-implemented": {"post": {}}})):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                changed = copy.deepcopy(actual)
                mutate(changed)
                alignment.validate_api(ROOT, "platform", changed)

    def test_dangling_and_external_schema_references_rejected(self):
        document = alignment.load(ROOT, "api/openapi/platform.json")
        for ref in ("#/components/schemas/NoSuchSchema", "https://example.invalid/schema"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                changed = copy.deepcopy(document)
                changed["components"]["schemas"]["ModelConfig"]["properties"]["api_key"] = {"$ref": ref}
                alignment.validate_refs(changed)

    def test_model_page_cannot_be_omitted_from_acceptance(self):
        routes = alignment.load(ROOT, "tests/acceptance/routes.json")
        routes["platform"].remove("/models")
        with self.assertRaises(ValueError):
            alignment.validate_routes(ROOT, routes, self.inventory)

    def test_nested_navigation_cannot_hide_system_routes(self):
        declared = alignment.platform_navigation_routes(ROOT)
        self.assertTrue({"/system", "/system/settings", "/system/accounts/users", "/system/audit/logins", "/response/policies", "/ai/mcp"}.issubset(declared))
        routes = alignment.load(ROOT, "tests/acceptance/routes.json")
        routes["platform"].remove("/system/settings")
        with self.assertRaises(ValueError):
            alignment.validate_routes(ROOT, routes, self.inventory)

    def test_invalid_navigation_contract_is_rejected(self):
        original = alignment.load(ROOT, "web/packages/shared/src/navigation.json")
        for mutate in (lambda data: data["screens"].append(copy.deepcopy(data["screens"][0])),
                       lambda data: data["screens"][0].update(path="https://external.invalid"),
                       lambda data: data["screens"][0].update(path="/assets/list"),
                       lambda data: data["screens"][0].update(workspace="missing"),
                       lambda data: data["workspaces"][0].update(group="missing")):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(original)
                mutate(changed)
                with mock.patch.object(alignment, "load", return_value=changed), self.assertRaises(ValueError):
                    alignment.platform_navigation_routes(ROOT)


if __name__ == "__main__":
    unittest.main()
