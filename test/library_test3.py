import unittest
import ast

from rule_engine import RuleEngine
from library import ImportRule, FunctionDefRule

class TestRuleEngineIntegration(unittest.TestCase):
    def setUp(self):
        # 初始化规则列表
        self.rules = [ImportRule(), FunctionDefRule()]
        # 将规则列表传入规则引擎的构造函数
        self.rule_engine = RuleEngine(self.rules)

    def test_import_rule_integration(self):
        # 测试导入规则对象与规则执行引擎的集成
        test_code = ast.parse("import os")
        # 执行规则引擎，检查规则是否能够正确检测到导入os模块的情况
        self.rule_engine.process_file("test_file.py", test_code)

        # 获取检测结果
        reports = self.rule_engine.errors

        # 断言是否检测到了预期的规则违反情况
        self.assertTrue(reports)

    def test_function_def_rule_integration(self):
        # 测试函数定义规则对象与规则执行引擎的集成
        test_code = ast.parse("def test_function():\n    pass")
        # 执行规则引擎，检查规则是否能够正确检测到函数定义为空的情况
        self.rule_engine.process_file("test_file.py", test_code)

        # 获取检测结果
        reports = self.rule_engine.errors

        # 断言是否检测到了预期的规则违反情况
        self.assertTrue(reports)

if __name__ == '__main__':
    unittest.main()
