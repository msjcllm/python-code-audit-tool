# coding:utf-8
# CVSS（Common Vulnerability Scoring System）评分通常分为以下几个级别：

# 0.0-3.9：低危（Low）
# 4.0-6.9：中危（Medium）
# 7.0-8.9：高危（High）
# 9.0-10.0：严重（Critical）

import sys
import ast

class Rule:
    def check(self, node):
        pass

# 危险模块导入检测
# os 模块检测
class ImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            if any(alias.name == "os" for alias in node.names):
                if len(node.names) == 1:  # 只有一个导入
                    # 返回规则对象本身以及错误信息和行号
                    return  "危险模块导入:os", node.lineno
        return None
    
    def get_XiangQing(self):
        return "检测Python代码中直接导入了os模块的情况,直接导入os模块时开发者可能会使用其中的函数(如os.path.join()、os.system()、os.popen()、os.setuid()和os.setgid()等)，可能导致代码执行不受控制的外部命令、文件操作不当、权限提升以及敏感信息泄露等安全问题。"

    def get_fix_suggestion(self):
        return "避免直接导入 os 模块，尽可能使用更安全的替代方法。如果确实需要使用 os 模块，应该对其使用进行严格的输入验证和过滤"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-400',
            'CVSS': 4.5,
            'level':'中危'
            # 其他漏洞信息
        }

# 危险模块导入检测
# subprocess 模块检测
class SubprocessImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                     if len(node.names) == 1:  # 只有一个导入
                        return f"危险模块导入: {alias.name}  ", node.lineno
        return None
    
    def get_XiangQing(self):
        return "直接导入subprocess模块可能导致命令注入漏洞。"
    
    def get_fix_suggestion(self):
        return "避免直接导入subprocess模块,使用更安全的替代方法,如使用subprocess.Popen()执行外部命令。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-78', 
            'CVSS': 7.5, 
            'level':'高危'
        }

# 危险模块导入检测
# shutil 模块检测
class ShutilImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "shutil":
                     if len(node.names) == 1:  # 只有一个导入
                        return f"危险模块导入: {alias.name}  ", node.lineno
        return None
    
    def get_XiangQing(self):
        return "直接导入shutil模块可能导致路径遍历攻击(Path Traversal)。"
    
    def get_fix_suggestion(self):
        return "避免直接导入shutil模块,使用更安全的替代方法,如使用os.path模块进行路径操作。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-22', 
            'CVSS': 6.5, 
            'level':'中危'
        }

# 危险模块导入检测
# pickle模块检测
class PickleImportRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pickle":
                     if len(node.names) == 1:  # 只有一个导入
                        return f"危险模块导入: {alias.name} ", node.lineno
        return None
    
    def get_XiangQing(self):
        return "直接导入pickle模块可能导致反序列化不受信任的数据,从而导致远程代码执行漏洞。"
    
    def get_fix_suggestion(self):
        return "避免直接使用pickle模块进行反序列化操作,使用更安全的替代方法,如JSON或XML等格式进行数据交换。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-94', 
            'CVSS': 8.0, 
            'level':'高危'
        }

# 危险函数及变量检测
# 空函数
class FunctionDefRule(Rule):
    def check(self, node):
        if isinstance(node, ast.FunctionDef):
            if len(node.body) == 0:
                return "空函数", node.lineno
        return None
    
    def get_XiangQing(self):
        return "检测到函数定义为空的情况。空函数可能导致程序运行时出现异常或未定义的行为。"
    
    def get_fix_suggestion(self):
        return "确保所有函数定义都包含有效的代码逻辑，避免定义空函数。如果函数确实不需要任何代码，则应该添加注释说明其用途。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-398',
            'CVSS': 3.5,
            'level': '低危'
            }

# 危险函数及变量检测
# 未明确类型声明的函数调用
class TypeErrorRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            # 假设我们想检查所有没有明确类型声明的函数调用
            if not isinstance(node.func, ast.Attribute) and not isinstance(node.func, ast.Name):
                return f"未明确声明类型的函数调用：{ast.unparse(node)}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到未明确声明类型的函数调用。这可能会导致类型不匹配错误，引发运行时异常或安全漏洞。"

    def get_fix_suggestion(self):
        return "在调用函数时，确保传入的参数具有正确的类型，并且对于可能的类型不匹配情况进行显式的类型转换或处理。建议添加类型声明以提高代码的可读性和健壮性。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-704',
            'CVSS': 3.7,
            'level': '低危'
            }

# 危险函数及变量检测
# 未使用的变量
class UnusedVariableRule:
    def __init__(self):
        self.names = set()

    def check(self, node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.names.add(target.id)
        elif isinstance(node, ast.Name):
            if node.id in self.names:
                self.names.remove(node.id)
        elif isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if isinstance(arg, ast.arg):
                    self.names.add(arg.arg)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                self.names.add(node.target.id)
        return None

    def final_check(self):
        if self.names:
            return f"未使用的变量：{', '.join(self.names)}"
        return None

    def get_XiangQing(self):
        return "检测到未使用的变量定义的情况。未使用的变量可能会增加代码复杂性并导致维护困难。"
    
    def get_fix_suggestion(self):
        return "删除未使用的变量定义，以减少代码复杂性并提高代码的可读性。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-563',
            'CVSS': 2.8,
            'level': '低危'
            }

# 危险数及变量检测
# 危险函数调用
class DangerousFunctionCallRule(Rule):
    dangerous_functions = ['eval', 'exec', 'execfile', '__import__']

    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.dangerous_functions:
                return f"危险函数调用：{node.func.id}", node.lineno
            elif isinstance(node.func, ast.Attribute) and node.func.attr in self.dangerous_functions:
                return f"危险函数调用：{node.func.attr}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到危险函数的调用，这些函数可能会导致安全漏洞，例如执行任意代码或加载恶意模块。"

    def get_fix_suggestion(self):
        return "避免使用危险函数，特别是在处理用户输入时。应该使用更安全的替代方法来执行相同的功能，例如使用更安全的解析器或库来执行动态代码。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-94',
            'CVSS': 7.5,
            'level': '高危'
            }

# 危险函数及变量检测
# 不安全函数调用
class InsecureFunctionRule(Rule):
    insecure_functions = ['open', 'os.system', 'os.popen', 'os.popen2', 'os.popen3', 'os.popen4',
                          'subprocess.Popen', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output',
                          'shlex', 'shutil.rmtree', 'shutil.move', 'shutil.copy',
                          'shutil.copyfile', 'shutil.copy2', 'shutil.copytree', 'shutil.make_archive']

    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.insecure_functions:
                return f"使用不安全的函数：{node.func.id}", node.lineno
            elif isinstance(node.func, ast.Attribute) and node.func.attr in self.insecure_functions:
                return f"使用不安全的函数：{node.func.attr}", node.lineno
        return None
    
    def get_XiangQing(self):
        return "检测到使用了不安全的函数。这些函数可能会导致安全漏洞，例如文件路径遍历攻击、系统调用漏洞、命令执行漏洞等。"

    def get_fix_suggestion(self):
        return "避免使用不安全的函数，尤其是涉及到文件操作、系统调用和命令执行的函数。应该选择更安全的替代方法，并对输入数据进行严格的验证和过滤。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-94',
            'CVSS': 7.5,
            'level': '高危'
            }

# 危险函数及变量检测
# 文件读取特征函数检测1
class FileReadRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function_name = self.get_function_name(node.func)
            if function_name in ['open', 'os.system', 'os.popen', 'subprocess.Popen', 'subprocess.run']:
                return f"文件读取漏洞的函数调用：{function_name}", node.lineno
        return None

    def get_function_name(self, node):
        if isinstance(node, ast.Attribute):
            value_name = self.get_value_name(node.value)
            attr_name = node.attr
            return f"{value_name}.{attr_name}"
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return ""

    def get_value_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_value_name(node.value)
        else:
            return ""

    def get_XiangQing(self):
        return "检测到可能存在文件读取漏洞的函数调用。这可能会导致恶意文件的读取，进而导致敏感信息泄露、远程命令执行等安全问题。"

    def get_fix_suggestion(self):
        return "避免使用不安全的文件读取函数，尤其是在处理用户输入时。应该使用更安全的替代方法来读取文件，例如使用安全的文件操作函数，并对文件路径进行严格的输入验证和过滤。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-22',
            'CVSS': 7.5,
            'level': '高危'
            }

# 文件读取特征函数检测2
class FileProtocolRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "open":
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Str):
                    file_path = node.args[0].s
                    if file_path.startswith("file://"):
                        return f"使用 file 协议读取文件：{file_path}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到可能存在文件读取漏洞的函数调用。这可能会导致恶意文件的读取，进而导致敏感信息泄露、远程命令执行等安全问题。"

    def get_fix_suggestion(self):
        return "避免使用 file:// 协议读取文件，尤其是在处理用户提供的文件路径时。应该使用相对路径或者其他安全的文件访问方式，以确保文件读取操作的安全性和可靠性"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-22',
            'CVSS': 7.5,
            'level':'高危'
        }

# 缓冲区溢出检测
#栈溢出
class StackOverflowRule(Rule):
    def check(self, node):
        if isinstance(node, ast.FunctionDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "buffer":
                            for value in stmt.value.elts:
                                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                                    buffer_size = len(value.value)
                                    if buffer_size > 100:  # 适当调整阈值
                                        return f"检测到栈溢出风险，缓冲区大小为 {buffer_size}", node.lineno
        return None
    
    def get_XiangQing(self):
        return "栈溢出是一种缓冲区溢出漏洞，当程序试图向栈中写入超出其分配的缓冲区大小的数据时发生。攻击者可能利用这种漏洞来执行任意代码，导致程序崩溃或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "避免在栈上分配过大的缓冲区，使用动态分配内存或栈保护技术来预防栈溢出漏洞的发生。在编写代码时，确保对用户输入进行适当的长度检查和过滤。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-121',
            'CVSS': 6.5,
            'level':'中危'
        }

# 缓冲区溢出检测
# 堆溢出
class HeapOverflowRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "buffer":
                    buffer_size = self.get_buffer_size(node.value)
                    if buffer_size > 1000:  # 适当调整阈值
                        return f"检测到堆溢出风险，缓冲区大小为 {buffer_size}", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "堆溢出是一种缓冲区溢出漏洞，当程序试图向堆中分配超出其分配的缓冲区大小的数据时发生。攻击者可能利用这种漏洞来执行任意代码，导致程序崩溃或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "避免在堆上分配过大的缓冲区，使用动态分配内存或堆保护技术来预防堆溢出漏洞的发生。在编写代码时，确保对用户输入进行适当的长度检查和过滤。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-122',
            'CVSS': 7.0,
            'level':'高危'
        }

# 缓冲区溢出检测
# 整数溢出
class IntegerOverflowRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "result":
                    if isinstance(node.value, ast.BinOp):
                        op = node.value.op
                        if isinstance(op, ast.Add) or isinstance(op, ast.Sub) or isinstance(op, ast.Mult):
                            left_val = self.get_value(node.value.left)
                            right_val = self.get_value(node.value.right)
                            if left_val is not None and right_val is not None:
                                if (op == ast.Add and left_val > sys.maxsize - right_val) or \
                                   (op == ast.Sub and left_val < -sys.maxsize + right_val) or \
                                   (op == ast.Mult and (left_val > 1 and right_val > sys.maxsize // left_val)):
                                    return f"检测到整数溢出风险", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "整数溢出是一种缓冲区漏洞,当程序试图对整数进行超出其表示范围的运算时发生。攻击者可能利用这种漏洞来执行任意代码,导致程序崩溃或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "在进行整数运算时,确保对结果进行范围检查,并采取适当的溢出处理措施,如使用更大的数据类型或异常处理机制。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-190',
            'CVSS': 7.5,
            'level':'高危'
        }

# sql注入漏洞检测
# 基于字符串拼接的SQL注入
class StringConcatSQLInjectionRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) and node.func.attr == "execute":
                    if "+" in node.func.value.value or "%" in node.func.value.value:
                        return "基于字符串拼接的SQL注入漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "基于字符串拼接的SQL注入漏洞是一种常见的安全漏洞,攻击者可以通过在SQL查询语句中插入恶意的代码来执行任意的数据库操作。"
    
    def get_fix_suggestion(self):
        return "避免在代码中使用字符串拼接构造SQL查询语句,而是应该使用参数化查询或ORM框架来执行数据库操作,以预防SQL注入漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 7.5,
            'level':'高危'
        }

# sql注入漏洞检测
# 基于动态构造的SQL注入
class DynamicSQLInjectionRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "cursor":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    query = node.args[0].value
                    if "{" in query and "}" in query:
                        return "基于动态构造的SQL注入漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "基于动态构造的SQL注入漏洞是一种常见的安全漏洞,攻击者可以通过在动态生成的SQL查询语句中插入恶意的代码来执行任意的数据库操作。"
    
    def get_fix_suggestion(self):
        return "避免在动态生成的SQL查询语句中直接插入用户输入,而是应该使用参数化查询或ORM框架来执行数据库操作,以预防SQL注入漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 7.0,
            'level':'高危'
        }

# sql注入漏洞检测
# ORM（对象关系映射）框架的SQL注入
class ORM_SQLInjectionRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in ("filter", "exclude", "get"):
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        query = node.args[0].value
                        if "{" in query and "}" in query:
                            return "ORM框架的SQL注入漏洞", node.lineno, self
        return None

    def get_XiangQing(self):
        return "ORM框架的SQL注入漏洞是一种常见的安全漏洞,攻击者可以通过在动态生成的SQL查询语句中插入恶意的代码来执行任意的数据库操作。"
    
    def get_fix_suggestion(self):
        return "在使用ORM框架进行数据库查询时,应该使用参数化查询或者框架提供的安全查询方法,避免直接拼接SQL字符串,以预防SQL注入漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 7.0,
            'level':'高危'
        }

# sql注入漏洞检测
# 嵌入式数据库查询的SQL注入
class EmbeddedDatabase_SQLInjectionRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in ("execute", "executemany"):
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        query = node.args[0].value
                        if "{" in query and "}" in query:
                            return "嵌入式数据库查询的SQL注入漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "嵌入式数据库查询的SQL注入漏洞是一种常见的安全漏洞,攻击者可以通过在动态生成的SQL查询语句中插入恶意的代码来执行任意的数据库操作。"
    
    def get_fix_suggestion(self):
        return "在进行嵌入式数据库查询时,应该使用参数化查询或者对输入进行适当的转义和过滤,避免直接拼接SQL字符串,以预防SQL注入漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 6.5,
            'level':'中危'
        }

# sql注入特征检测
# 动态
class SQLInjectionRule1(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if self.is_sql_query(node):
                if self.has_potential_injection(node):
                    return f"SQL 注入漏洞风险：{ast.unparse(node)}", node.lineno
        return None

    def is_sql_query(self, node):
        # 检查是否是执行 SQL 查询的函数，例如 execute()、query() 等
        sql_query_functions = ['execute', 'query', 'executemany', 'executescript']
        if isinstance(node.func, ast.Attribute) and node.func.attr.lower() in sql_query_functions:
            return True
        return False

    def has_potential_injection(self, node):
        # 检查参数是否是字符串常量，并且是否包含可能的注入关键字
        if len(node.args) >= 2:
            query_string = node.args[0]
            parameters = node.args[1:]
            if isinstance(query_string, ast.Constant) and isinstance(query_string.value, str):
                query_text = query_string.value
                for param in parameters:
                    if isinstance(param, ast.Constant) and isinstance(param.value, str):
                        param_text = param.value
                        if self.is_potential_injection(query_text, param_text):
                            return True
        return False

    def is_potential_injection(self, query_text, param_text):
        # 检查参数是否直接拼接到查询字符串中，并且是否包含可能的注入关键字
        if param_text in query_text:
            return True
        # 检查是否包含可能的注入关键字
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'DROP', 'TRUNCATE', 'UNION', 'JOIN', 'ALTER', 'CREATE']
        for keyword in sql_keywords:
            if keyword in param_text.upper():
                return True
        return False

    def get_XiangQing(self):
        return "检测到存在 SQL 注入漏洞风险，即动态生成的 SQL 语句中可能存在恶意注入代码，导致数据库被攻击者控制。"

    def get_fix_suggestion(self):
        return "应该使用参数化查询或者 ORM 框架等安全的方式来执行 SQL 查询，并避免直接拼接用户输入到 SQL 语句中。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 9.8,
            'level': '严重'
        }

# sql注入特征检测
# 静态
class SQLInjectionRule2(Rule):
    def __init__(self):
        self.sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'DROP', 'TRUNCATE', 'UNION', 'JOIN', 'ALTER', 'CREATE']

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function_name = node.func.attr.lower()
            if function_name in ['execute', 'query', 'executemany', 'executescript']:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if self.contains_sql_keywords(arg.value):
                            return f" 存在SQL 注入漏洞风险：{ast.unparse(node)}", node.lineno
                    elif isinstance(arg, ast.FormattedValue):
                        # 检查f-string中的字符串部分
                        if isinstance(arg.value, ast.Constant) and isinstance(arg.value.value, str):
                            if self.contains_sql_keywords(arg.value.value):
                                return f"存在SQL 注入漏洞风险：{ast.unparse(node)}", node.lineno
                    elif isinstance(arg, ast.JoinedStr):
                        # 检查f-string中的拼接部分
                        for val in arg.values:
                            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                if self.contains_sql_keywords(val.value):
                                    return f"存在SQL 注入漏洞风险：{ast.unparse(node)}", node.lineno
        return None

    def contains_sql_keywords(self, text):
        upper_text = text.upper()
        for keyword in self.sql_keywords:
            if keyword in upper_text:
                return True
        return False

    def get_XiangQing(self):
        return "检测到存在 SQL 注入漏洞风险，即动态生成的 SQL 语句中可能存在恶意注入代码，导致数据库被攻击者控制。"

    def get_fix_suggestion(self):
        return "应该使用参数化查询或者 ORM 框架等安全的方式来执行 SQL 查询，并避免直接拼接用户输入到 SQL 语句中。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-89',
            'CVSS': 9.8,
            'level': '严重'
        }

# 跨站脚本XSS检测
# DOM型XSS
class DOMXSSRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute) and isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "document":
                    if node.func.attr in ["write", "writeln"]:
                        return "DOM型XSS漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "DOM型XSS漏洞是一种常见的跨站脚本漏洞,攻击者可以通过在客户端执行的JavaScript代码中插入恶意的脚本来获取用户信息或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "避免直接将用户输入的数据输出到JavaScript代码中,对用户输入的数据进行适当的转义和过滤,以预防DOM型XSS漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-79',
            'CVSS': 6.5,
            'level':'中危'
        }

# 跨站脚本XSS检测
# 未经过滤的用户输入的XSS
class UnfilteredInputXSSRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id in ["innerHTML", "outerHTML", "textContent", "setAttribute"]:
                    return "未经过滤的用户输入的XSS漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "未经过滤的用户输入的XSS漏洞是一种常见的跨站脚本漏洞,攻击者可以通过在网页中插入恶意的脚本来获取用户信息或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "对用户输入的数据进行适当的转义和过滤,确保在将其输出到HTML页面中时不会执行任意的JavaScript代码,以预防未经过滤的用户输入的XSS漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-79',
            'CVSS': 7.0,
            'level':'高危'
        }

# 跨站脚本XSS检测
# 基于框架和模板 的XSS
class FrameworkTemplateXSSRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "render_template":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if "{{" in arg.value and "}}" in arg.value:
                                return "基于框架和模板的XSS漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "基于框架和模板的XSS漏洞是一种常见的跨站脚本漏洞,攻击者可以通过在网页模板中插入恶意的脚本来获取用户信息或执行恶意操作。"
    
    def get_fix_suggestion(self):
        return "在使用框架和模板引擎时,确保对用户输入的数据进行适当的转义和过滤,以预防基于框架和模板的XSS漏洞的发生。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-79',
            'CVSS': 7.5,
            'level':'高危'
        }

# 未授权访问检测
# 目录遍历
class DirectoryTraversalRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                    if node.func.attr in ["open", "exists"]:  # 根据实际情况调整
                        if "../" in node.func.value.value:
                            return "存在目录遍历漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "目录遍历漏洞可能导致攻击者访问应用程序文件系统中的敏感文件或目录。"
    
    def get_fix_suggestion(self):
        return "使用安全的文件路径检查和访问控制机制来防止目录遍历漏洞。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-22', 
            'CVSS': 7.0, 
            'level':'高危'
            }

# 未授权访问检测
# 未验证的重定向漏洞
class UnvalidatedRedirectRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "redirect":
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        if "http://" in node.args[0].value or "https://" in node.args[0].value:
                            return "存在未验证的重定向漏洞", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "未验证的重定向漏洞可能被用于进行钓鱼攻击或重定向到恶意站点。"
    
    def get_fix_suggestion(self):
        return "始终对重定向目标进行验证，确保重定向目标是受信任的。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-601', 
            'CVSS': 5.8, 
            'level':'中危'
            }

# 未授权访问检测
# 未经授权的文件访问漏洞
class UnauthorizedFileAccessRule(Rule):
    def check(self, node):
        if not isinstance(node, ast.Call):
            return None
        
        if not isinstance(node.func, ast.Attribute):
            return None
        
        if node.func.attr not in ["open", "read", "write"]:
            return None
        
        if not node.args:
            return None
        
        if not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            return None
        
        filepath = node.args[0].value
        if "/etc/" in filepath or "C:\\Windows\\" in filepath:
            return "存在未经授权的文件访问漏洞", node.lineno, self
        
        return None
    
    def get_XiangQing(self):
        return "未经授权的文件访问漏洞可能允许攻击者访问或修改应用程序文件系统中的敏感文件。"
    
    def get_fix_suggestion(self):
        return "使用访问控制和权限验证来限制对敏感文件的访问，并确保文件操作受到充分的身份验证和授权。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-22', 
            'CVSS': 6.2, 
            'level':'中危'
            }

# 弱加密算法
# 使用弱加密算法（如DES、MD5）的检测
class WeakEncryptionAlgorithmRule(Rule):
    def check(self, node):
        weak_algorithms = ["DES", "MD5"]  # 弱加密算法列表
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in weak_algorithms:
                    return f"使用弱加密算法 '{node.func.attr}' 的可能性", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "使用弱加密算法(如DES、MD5)可能导致密码等敏感数据泄露或被攻击者轻易破解。"
    
    def get_fix_suggestion(self):
        return "使用更安全的加密算法(如AES、SHA-256等)替换弱加密算法,以确保数据的安全性。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-326', 
            'CVSS': 5.8, 
            'level':'中危'
            }

# 弱加密算法   
# 使用固定密钥的检测
class FixedEncryptionKeyRule(Rule):
    def check(self, node):
        if not isinstance(node, ast.Call):
            return None
        
        if not isinstance(node.func, ast.Attribute):
            return None
        
        if node.func.attr != "encrypt":
            return None
        
        if not node.args:
            return None
        
        if len(node.args) <= 1:
            return None
        
        if not isinstance(node.args[1], ast.Constant) or not isinstance(node.args[1].value, str):
            return None
        
        if len(node.args[1].value) > 8:
            return None
        
        return "使用固定密钥进行加密", node.lineno, self
    
    def get_XiangQing(self):
        return "使用固定密钥进行加密可能使得加密算法变得容易受到攻击,从而导致数据泄露或破解。"
    
    def get_fix_suggestion(self):
        return "使用随机生成的且足够复杂的密钥来替代固定密钥,以提高加密算法的安全性。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-321', 
            'CVSS': 6.5, 
            'level':'中危'
            }

# 弱加密算法
# 使用无盐（salt）的检测
class NoSaltRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "encrypt":
                    if len(node.args) == 1:  # 没有盐参数
                        return "加密时未使用盐", node.lineno, self
        return None
    
    def get_XiangQing(self):
        return "在加密过程中使用盐(salt)可以增加密码的破解难度,提高加密算法的安全性。"
    
    def get_fix_suggestion(self):
        return "在加密过程中使用随机生成的盐值,以增加密码的复杂性和安全性。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-329', 
            'CVSS': 6.2, 
            'level':'中危'
            }

# 未处理的异常检测
class ExceptionNotHandledRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Raise):
            if not any(isinstance(n, ast.ExceptHandler) for n in ast.walk(node)):
                return f"未处理的异常：{ast.unparse(node)}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到未处理的异常。在Python代码中,如果抛出了异常但没有进行适当的处理,可能会导致程序终止或者导致意外行为。"

    def get_fix_suggestion(self):
        return "在代码中添加适当的异常处理机制,以捕获并处理可能出现的异常情况,确保代码的稳定性和安全性.建议使用 try-except 块来捕获异常,并进行相应的处理。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-755',
            'CVSS': 5.0,
            'level': '中危'
            }

# 反序列化函数漏洞检测
# pickle 反序列化检测
class PickleDeserializationRule(Rule):
    insecure_functions = ['pickle.loads', 'pickle.load']

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function_name = self.get_function_name(node.func)
            if function_name in self.insecure_functions:
                return f" pickle 反序列化漏洞的函数调用：{function_name}", node.lineno
        return None

    def get_function_name(self, node):
        if isinstance(node, ast.Attribute):
            value_name = self.get_value_name(node.value)
            attr_name = node.attr
            return f"{value_name}.{attr_name}"
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return ""

    def get_value_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_value_name(node.value)
        else:
            return ""

    def get_XiangQing(self):
        return "检测到使用了不安全的 pickle 反序列化函数。这可能会导致恶意数据的反序列化，从而导致远程代码执行等安全漏洞。"

    def get_fix_suggestion(self):
        return "避免使用不安全的 pickle 反序列化函数，尽可能使用更安全的替代方法。对于需要进行反序列化操作的数据，应该使用安全的序列化和反序列化库，并对数据源进行严格的验证和过滤。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-502',
            'CVSS': 9.8,
            'level': '严重'
            }

# 反序列化函数漏洞检测
# JSON 反序列化检测
class JsonDeserializationRule(Rule):
    insecure_functions = ['json.loads']

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function_name = self.get_function_name(node.func)
            if function_name in self.insecure_functions:
                return f"JSON 反序列化漏洞的函数调用：{function_name}", node.lineno
        return None

    def get_function_name(self, node):
        if isinstance(node, ast.Attribute):
            value_name = self.get_value_name(node.value)
            attr_name = node.attr
            return f"{value_name}.{attr_name}"
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return ""

    def get_value_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_value_name(node.value)
        else:
            return ""

    def get_XiangQing(self):
        return "检测到使用了不安全的 JSON 反序列化函数。这可能会导致恶意数据的反序列化，从而导致远程代码执行等安全漏洞。"

    def get_fix_suggestion(self):
        return "避免使用不安全的 JSON 反序列化函数，尽可能使用更安全的替代方法。对于需要进行反序列化操作的数据，应该使用安全的序列化和反序列化库，并对数据源进行严格的验证和过滤。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-502',
            'CVSS': 9.8,
            'level': '严重'
            }

# 模板注入（Server-Side Template Injection，SSTI）漏洞检测
# 模板注入SSTI特征检测1
class TemplateInjectionRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "Template":
                    return " Template 类的导入"

        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "Template":
                    return "对 Template 类的实例化"

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ["render", "render_template"]:
                return f"模板渲染函数的调用：{ast.unparse(node)}", node.lineno
        
        return None

    def get_XiangQing(self):
        return "模板注入(Server-Side Template Injection,SSTI)是一种常见的 Web 漏洞,攻击者通过在模板中注入恶意代码,可以执行任意命令或者获取敏感信息。"

    def get_fix_suggestion(self):
        return "应该使用模板渲染引擎的安全模式,避免直接将用户输入作为模板渲染的内容。另外,尽量不要在模板中执行复杂的表达式或函数调用。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-94',
            'CVSS': 8.6,
            'level': '高危'
        }

# 模板注入（Server-Side Template Injection，SSTI）漏洞检测
# 模板注入SSTI特征检测2
class TemplateInjectionRule2(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function_name = node.func.attr.lower()
            if function_name in ['render', 'render_template']:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if self.contains_template_keywords(arg.value):
                            return f"模板注入漏洞风险：{ast.unparse(node)}", node.lineno
        return None

    def contains_template_keywords(self, text):
        template_keywords = ['{{', '}}', '{%', '%}']
        for keyword in template_keywords:
            if keyword in text:
                return True
        return False

    def get_XiangQing(self):
        return "模板注入(Server-Side Template Injection,SSTI)是一种常见的 Web 漏洞，攻击者通过在模板中注入恶意代码，可以执行任意命令或者获取敏感信息。"

    def get_fix_suggestion(self):
        return "应该使用模板渲染引擎的安全模式，避免直接将用户输入作为模板渲染的内容。另外，尽量不要在模板中执行复杂的表达式或函数调用。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-94',
            'CVSS': 8.6,
            'level': '高危'
        }

# XXE 漏洞检测
# XXE
class XXECheckRule(Rule):
    def check(self, node):
        if isinstance(node, ast.ImportFrom) and node.module == "xml.etree.ElementTree":
            return " XXE 漏洞的导入: xml.etree.ElementTree", node.lineno

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "parse":
            if self.is_unsafe_parse(node):
                return " XXE 漏洞的解析: xml.etree.ElementTree.parse()", node.lineno

        return None

    def is_unsafe_parse(self, node):
        if len(node.args) > 0:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and "DTD" in first_arg.value:
                return True
        return False

    def get_XiangQing(self):
        return "检测到直接导入 xml.etree.ElementTree 模块的情况，可能存在 XXE 漏洞风险。"

    def get_fix_suggestion(self):
        return "避免在解析 XML 数据时启用外部实体并执行 DTD,应该禁用外部实体并且仅解析受信任的 XML 数据。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-611',
            'CVSS': 7.5,
            'level': '高危'
        }

# XXE 漏洞检测
# 直接实例化XML解析器
class DirectXMLParserInstantiationRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ["ET.parse", "ET.XML"]:
                return "直接实例化XML解析器的调用", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到直接实例化XML解析器的调用,可能存在XXE漏洞风险。"

    def get_fix_suggestion(self):
        return "避免直接实例化XML解析器,应该使用安全的方式解析XML数据,如使用解析器的安全模式或禁用外部实体解析功能。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-611',
            'CVSS': 7.5,
            'level': '高危'
        }

# XXE 漏洞检测
# 从用户输入构造XML
class ConstructXMLFromUserInputRule(Rule):
    def check(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Name):
                return "从用户输入构造XML的情况", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到从用户输入构造XML的情况,可能存在XXE漏洞风险。"

    def get_fix_suggestion(self):
        return "避免直接将用户输入拼接到XML中,应该对用户输入进行严格的过滤和验证,确保不包含恶意的外部实体或DTD定义。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-611',
            'CVSS': 7.5,
            'level': '高危'
        }
    
# XXE 漏洞检测
# 加载外部XML文件
class LoadExternalXMLFileRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "parse" and isinstance(node.func.value, ast.Name) and node.func.value.id == "ET":
                if len(node.args) > 0 and isinstance(node.args[0], ast.Str):
                    file_path = node.args[0].s
                    if file_path.startswith("http://") or file_path.startswith("https://"):
                        return "外部XML文件的调用", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到加载外部XML文件的调用,可能存在XXE漏洞风险。"

    def get_fix_suggestion(self):
        return "避免直接加载外部XML文件,应该对外部数据进行严格的过滤和验证,确保不包含恶意的外部实体或DTD定义。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-611',
            'CVSS': 7.5,
            'level': '高危'
        }

# SSRF漏洞检测
# SSRF 特征检测
class SSRFRule(Rule):
    def __init__(self):
        self.ssrf_functions = ['pycurl.Curl().setopt', 'urllib.urlopen', 'urllib2.urlopen', 'urllib3.PoolManager().request', 'requests.get', 'requests.post']

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func_name = self.get_function_name(node)
            if func_name in self.ssrf_functions:
                return f"存在 SSRF 漏洞风险：{ast.unparse(node)}", node.lineno
        return None

    def get_function_name(self, node):
        func_name = ''
        try:
            func_name = node.func.value.id + '.' + node.func.attr
        except AttributeError:
            pass
        return func_name

    def get_XiangQing(self):
        return "检测Python代码中直接导入了os模块的情况,而直接导入os模块可能会导致对系统资源的未受控制的访问,这可能会引发各种安全问题，比如路径遍历攻击等。"

    def get_fix_suggestion(self):
        return "建议使用。"
    
    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-123',
            'CVSS': 7.5,
            'level':'Medium'
            # 其他漏洞信息
        }

# SSRF漏洞检测
# 直接使用用户输入构造URL
class SSRFURLFromUserInputRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "request" and len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    url = node.args[1].value
                    if is_user_controlled(url):
                        return f"从用户输入构造URL: {url}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到直接使用用户输入构造URL的情况,可能存在SSRF漏洞风险。"

    def get_fix_suggestion(self):
        return "避免直接将用户输入构造URL,应该对URL参数进行严格的验证和过滤,确保只能访问预期的资源。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-918',
            'CVSS': 7.5,
            'level': '高危'
        }

def is_user_controlled(url):
    # 实现判断URL是否受用户控制的逻辑，例如检查是否包含特定的协议或主机名等
    # 这里假设简单地判断是否以"http://"或"https://"开头
    return url.startswith("http://") or url.startswith("https://")

# SSRF漏洞检测
# 使用不受信任的协议
class SSRFUntrustedProtocolRule(Rule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "request" and len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    url = node.args[1].value
                    if has_untrusted_protocol(url):
                        return f"使用不受信任协议构造URL: {url}", node.lineno
        return None

    def get_XiangQing(self):
        return "检测到使用不受信任协议构造URL的情况,可能存在SSRF漏洞风险。"

    def get_fix_suggestion(self):
        return "避免使用不受信任的协议,限制URL仅允许使用安全的协议,例如http:// 或 https://。"

    def get_vulnerability_info(self):
        return {
            'CWE': 'CWE-918',
            'CVSS': 7.5,
            'level': '高危'
        }

def has_untrusted_protocol(url):
    # 实现判断URL是否使用不受信任的协议的逻辑
    untrusted_protocols = ["file://", "dict://", "gopher://"]  # 添加其他不受信任的协议
    for protocol in untrusted_protocols:
        if url.startswith(protocol):
            return True
    return False


# 编码规范检查



def load_rules():
    return [ImportRule(), 
            SubprocessImportRule(),
            ShutilImportRule(),
            PickleImportRule(),
            FunctionDefRule(),
            TypeErrorRule(),
            UnusedVariableRule(),
            DangerousFunctionCallRule(),
            InsecureFunctionRule(),
            FileReadRule(),
            FileProtocolRule(),
            StackOverflowRule(),
            HeapOverflowRule(),
            IntegerOverflowRule(),
            StringConcatSQLInjectionRule(),
            DynamicSQLInjectionRule(),
            ORM_SQLInjectionRule(),
            EmbeddedDatabase_SQLInjectionRule(),
            SQLInjectionRule1(),
            SQLInjectionRule2(),
            DOMXSSRule(),
            UnfilteredInputXSSRule(),
            FrameworkTemplateXSSRule(),
            DirectoryTraversalRule(),
            UnvalidatedRedirectRule(),
            UnauthorizedFileAccessRule(),
            WeakEncryptionAlgorithmRule(),
            FixedEncryptionKeyRule(),
            NoSaltRule(),
            ExceptionNotHandledRule(), 
            PickleDeserializationRule(),
            JsonDeserializationRule(),
            TemplateInjectionRule(),
            TemplateInjectionRule2(),
            XXECheckRule(),
            DirectXMLParserInstantiationRule(),
            ConstructXMLFromUserInputRule(),
            LoadExternalXMLFileRule(),
            SSRFRule(),
            SSRFURLFromUserInputRule(),
            SSRFUntrustedProtocolRule(),
            
            ]



