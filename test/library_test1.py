import unittest
from library import ImportRule, FunctionDefRule, load_rules

class TestRuleCreation(unittest.TestCase):
    def test_import_rule_creation(self):
        # 测试导入规则对象的创建
        import_rule = ImportRule()

        # 断言规则对象是否是 ImportRule 类的实例
        self.assertIsInstance(import_rule, ImportRule)
        # 断言规则对象是否正确实现了 check 方法
        self.assertTrue(hasattr(import_rule, 'check'))
        # 断言规则对象是否正确实现了 get_fix_suggestion 方法
        self.assertTrue(hasattr(import_rule, 'get_fix_suggestion'))
        # 断言规则对象是否正确实现了 get_vulnerability_info 方法
        self.assertTrue(hasattr(import_rule, 'get_vulnerability_info'))

    def test_function_def_rule_creation(self):
        # 测试函数定义规则对象的创建
        function_def_rule = FunctionDefRule()

        # 断言规则对象是否是 FunctionDefRule 类的实例
        self.assertIsInstance(function_def_rule, FunctionDefRule)
        # 断言规则对象是否正确实现了 check 方法
        self.assertTrue(hasattr(function_def_rule, 'check'))
        # 断言规则对象是否正确实现了 get_fix_suggestion 方法
        self.assertTrue(hasattr(function_def_rule, 'get_fix_suggestion'))
        # 断言规则对象是否正确实现了 get_vulnerability_info 方法
        self.assertTrue(hasattr(function_def_rule, 'get_vulnerability_info'))

    def test_load_rules(self):
        # 测试加载规则函数 load_rules 是否能够成功加载规则列表
        rules = load_rules()

        # 断言返回的规则列表是否包含 ImportRule 和 FunctionDefRule 对象
        self.assertTrue(any(isinstance(rule, ImportRule) for rule in rules))
        self.assertTrue(any(isinstance(rule, FunctionDefRule) for rule in rules))

if __name__ == '__main__':
    unittest.main()
