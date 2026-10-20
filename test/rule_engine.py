# coding:utf-8



import ast

class RuleEngine(ast.NodeVisitor):
    def __init__(self, rules):
        self.rules = rules
        self.errors = []
        self.current_file = None

    def visit(self, tree):
        # 前序遍历 AST
        for node in ast.walk(tree):
            self.check(node)

    def check(self, node):
        # 检查当前节点是否违反了规则
        for rule in self.rules:
            error = rule.check(node)
            if error is not None:
                # 获取风险节点的行号
                lineno = getattr(node, "lineno", None)
                if lineno is not None:
                    error_message = f"{error} (Line {lineno})"
                else:
                    error_message = error

                # 获取修复建议
                fix_suggestion = rule.get_fix_suggestion()
                # 添加CWE、CVSS信息
                vulnerability_info = rule.get_vulnerability_info()
                
                # 将风险部分一起记录下来
                self.errors.append({
                    'file': self.current_file,
                    "line": lineno,
                    'error': error,
                    'code': ast.unparse(node),
                    # 存储规则对象的引用
                    'rule': rule,  
                    'suggestion': fix_suggestion,
                    'CWE': vulnerability_info['CWE'],  # 添加 CWE 信息
                    'CVSS': vulnerability_info['CVSS'],  # 添加 CVSS 信息
                })  

    def process_file(self, file, tree):
        # 记录当前处理的文件路径
        self.current_file = file
        self.visit(tree)
        