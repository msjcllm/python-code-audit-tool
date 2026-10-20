import unittest
import ast
from rule_engine import RuleEngine
from library import load_rules

class TestRuleMatching(unittest.TestCase):
    def test_rule_matching(self):
        # 创建规则引擎并加载规则集
        rules = load_rules()  # 假设有一个函数 load_rules() 用于加载规则集
        rule_engine = RuleEngine(rules)

        # 创建一个简单的 Python 代码字符串，并将其解析为 AST 节点
        code = "x = 10\nif x == 10:\n    print('Hello, world!')"
        tree = ast.parse(code)

        # 对 AST 节点进行检查
        rule_engine.visit(tree)

        # 检查规则引擎是否正确记录了违反规则的情况
        self.assertEqual(len(rule_engine.errors), 0, "规则匹配测试失败，未正确识别违反规则的情况")

if __name__ == "__main__":
    unittest.main()
