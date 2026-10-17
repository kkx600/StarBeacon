import importlib.util
import pathlib
import unittest
from unittest.mock import patch


path = pathlib.Path(__file__).resolve().parents[1] / "remote_acceptance.py"
spec = importlib.util.spec_from_file_location("remote_dependency_secrets", path)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class DependencySecretsTests(unittest.TestCase):
    def test_numeric_prefix_cannot_change_nats_token_type(self):
        # 复现配置变量展开时的数字词法歧义，不降低随机熵或把变量引用放进引号。
        with patch.object(acceptance.secrets, "token_hex", return_value="7a" * 24) as random:
            values = acceptance.dependency_secrets()
        self.assertEqual(values["NATS_TOKEN"], "sb_" + "7a" * 24)
        self.assertEqual(set(values), {"POSTGRES_PASSWORD", "SB_RUNTIME_DB_PASSWORD", "REDIS_PASSWORD", "NATS_TOKEN"})
        self.assertEqual([call.args for call in random.call_args_list], [(24,)] * 4)
        self.assertTrue(all(len(value) == 48 for key, value in values.items() if key != "NATS_TOKEN"))

    def test_independent_staging_keeps_fresh_private_values(self):
        first, second = acceptance.dependency_secrets(), acceptance.dependency_secrets()
        self.assertTrue(all(first[key] != second[key] for key in first))
        self.assertRegex(first["NATS_TOKEN"], r"^sb_[a-f0-9]{48}$")


if __name__ == "__main__":
    unittest.main()
