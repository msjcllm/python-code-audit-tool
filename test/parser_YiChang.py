import unittest
import os
from code_parser import CodeParser

class TestCodeParser(unittest.TestCase):
    def setUp(self):
        self.test_root_dir = "test_code"
        # 创建 result 文件夹
        result_folder = 'result' 
        if not os.path.exists(result_folder):
            os.makedirs(result_folder)
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

    def test_parse_code(self):
        # 初始化 CodeParser 对象
        code_parser = CodeParser(self.test_root_dir)
        # 解析代码，获取解析结果
        error_messages = list(code_parser.trees)
        # 检查是否有语法错误
        self.assertEqual(len(error_messages), 1, "应该存在一个语法错误")


if __name__ == "__main__":
    unittest.main()
