import unittest
from rule_engine import RuleEngine

class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        # 模拟一个规则集
        self.mock_rules = [
            MockRule("Rule 1", "Fix suggestion 1", {"CWE": "CWE-123", "CVSS": 7.5}),
            MockRule("Rule 2", "Fix suggestion 2", {"CWE": "CWE-456", "CVSS": 5.0}),
            # 添加更多模拟规则...
        ]

    def test_rule_set_loading(self):
        # 测试规则集加载成功
        rule_engine = RuleEngine(self.mock_rules)
        self.assertEqual(len(rule_engine.rules), len(self.mock_rules), "规则集加载失败")

    def test_empty_rule_set(self):
        # 测试空规则集加载
        rule_engine = RuleEngine([])
        self.assertEqual(len(rule_engine.rules), 0, "规则集为空时未正确处理")

    # 添加其他测试用例...

# 模拟规则对象
class MockRule:
    def __init__(self, error, fix_suggestion, vulnerability_info):
        self.error = error
        self.fix_suggestion = fix_suggestion
        self.vulnerability_info = vulnerability_info

    def check(self, node):
        return self.error

    def get_fix_suggestion(self):
        return self.fix_suggestion

    def get_vulnerability_info(self):
        return self.vulnerability_info

if __name__ == "__main__":
    unittest.main()
