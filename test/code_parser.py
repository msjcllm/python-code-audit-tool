# code_parser.py

import ast
import os

class CodeParser:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        # 设置 AST 文件夹的生成路径
        self.ast_folder = os.path.join(os.path.dirname(__file__), "AST")
        if not os.path.exists(self.ast_folder):
            os.makedirs(self.ast_folder)

    @property
    def trees(self):
        error_messages = []  # 存储错误信息的列表
        total_files = 0  # 总文件数计数器
        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith('.py'):
                    # 每遇到一个 .py 文件，总文件数加1
                    total_files += 1  
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        code = f.read()
                        try:
                            ast_tree = ast.parse(code)
                            # 将ast语法树以源码文件_ast_txt的名字命名并保存
                            ast_file_path = os.path.join(self.ast_folder, f"{os.path.splitext(file)[0]}_ast.txt")
                            with open(ast_file_path, "w", encoding="utf-8") as ast_file:
                                ast_file.write(ast.dump(ast_tree, indent=4))
                            yield os.path.join(root, file), ast_tree
                        except SyntaxError as e:
                            error_message = f"语法错误在文件 {os.path.join(root, file)}: {e}"
                            error_messages.append(error_message)

        result_dir = os.path.join(os.path.dirname(__file__), "result")
        errors_file_path = os.path.join(result_dir, "errors.txt")
        with open(errors_file_path, "w", encoding="utf-8") as error_file:
            for error_message in error_messages:
                error_file.write(error_message + "\n")

        return error_messages
