import unittest
import os
from code_parser import CodeParser

class TestCodeParser(unittest.TestCase):
    def setUp(self):
        self.test_root_dir = "test_code"
        # 创建测试代码文件夹和测试文件
        os.makedirs(self.test_root_dir, exist_ok=True)
        with open(os.path.join(self.test_root_dir, "test_file.py"), "w", encoding="utf-8") as f:
            f.write("x = 1\nprint(x)\n")
        with open(os.path.join(self.test_root_dir, "test_file_with_syntax_error.py"), "w", encoding="utf-8") as f:
            f.write("print(1\n")
        
    def tearDown(self):
        # 清理测试文件夹和测试文件
        os.remove(os.path.join(self.test_root_dir, "test_file.py"))
        os.remove(os.path.join(self.test_root_dir, "test_file_with_syntax_error.py"))
        os.rmdir(self.test_root_dir)

    def test_generate_ast(self):
        # 初始化 CodeParser 对象
        code_parser = CodeParser(self.test_root_dir)
        # 检查是否正确生成了 AST 文件
        self.assertTrue(os.path.exists(code_parser.ast_folder), "AST 文件夹应该存在")
        for root, _, files in os.walk(code_parser.ast_folder):
            for file in files:
                self.assertTrue(file.endswith('_ast.txt'), "AST 文件应该存在")

    def test_syntax_error_detection(self):
        # 初始化 CodeParser 对象
        code_parser = CodeParser(self.test_root_dir)
        # 检查是否正确生成了错误信息文件
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(__file__), "result", "errors.txt")), "错误信息文件应该存在")

if __name__ == "__main__":
    unittest.main()
