# coding:utf-8



import ast

class Rule:
    def check(self, node):
        pass

# 模块检测
class ImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            if any(alias.name == "os" for alias in node.names):
                # 返回规则对象本身以及错误信息和行号
                return  "检测到直接导入 'os' 模块", node.lineno, self
        return None
    
    def get_fix_suggestion(self):
        return "避免直接导入 os 模块，尽可能使用更安全的替代方法。如果确实需要使用 os 模块，应该对其使用进行严格的输入验证和过滤"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-123',
            'CVSS': 7.5,
            # 其他漏洞信息
        }

# 函数及变量检测
class FunctionDefRule(Rule):
    def check(self, node):
        if isinstance(node, ast.FunctionDef):
            if len(node.body) == 0:
                return "检测到函数定义为空", node.lineno
        return None
    
    def get_fix_suggestion(self):
        return "确保所有函数定义都包含有效的代码逻辑，避免定义空函数"

    def get_vulnerability_info(self):
        return {
            'CWE': '无',
            'CVSS': 3.5,
            # 其他漏洞信息
        }

# 用于library_test.2.py的测试
#class FunctionDefRule(Rule):
    #def check(self, node):
        if isinstance(node, ast.FunctionDef):
            if len(node.body) == 0:
                return "检测到函数定义为空", node.lineno
            for statement in node.body:
                if not isinstance(statement, ast.Pass):
                    return None  # 函数体中有非空语句，不符合空函数定义条件
            return "检测到函数定义为空", node.lineno
        return None


def load_rules():
    return [ImportRule(), 
            FunctionDefRule(), 
            ]