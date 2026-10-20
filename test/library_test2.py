import unittest
import ast
from library import ImportRule, FunctionDefRule

class TestRuleCheck(unittest.TestCase):
    def test_import_rule_check(self):
        # 创建 ImportRule 实例
        import_rule = ImportRule()

        # 创建一个包含直接导入 os 模块的 Import 节点
        code = "import os"
        node = ast.parse(code).body[0]

        # 检查规则
        result = import_rule.check(node)

        # 断言结果是否符合预期
        expected_result = ("检测到直接导入 'os' 模块", 1, import_rule)
        self.assertEqual(result, expected_result)

    def test_function_def_rule_check(self):
        # 创建 FunctionDefRule 实例
        function_def_rule = FunctionDefRule()

        # 创建一个空函数定义的 FunctionDef 节点
        code = "def empty_function():\n    pass"
        node = ast.parse(code).body[0]

        # 检查规则
        result = function_def_rule.check(node)

        # 打印实际结果
        print("Actual result:", result)

        # 断言结果是否符合预期
        expected_result = ("检测到函数定义为空", 1)
        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
