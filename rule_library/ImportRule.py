import ast

class Rule:
    def check(self, node):
        pass

# 模块检测
class ImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            if any(alias.name == "os" for alias in node.names):
                return "检测到直接导入 'os' 模块", node.lineno
        return None