import unittest
import os

from report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    def test_generate_html_report(self):
        # 模拟一些错误信息
        errors = [
            {
                'file': 'test_file.py',
                'line': 10,
                'error': 'Syntax error',
                'code': 'x = 1\nprint(x',  # 模拟错误代码片段
                'CWE': 'CWE-123',
                'CVSS': 7.5,
                'rule': None  # 为了简化测试，此处不使用规则对象
            },
            # 添加更多的错误信息...
        ]

        # 初始化报告生成器
        report_generator = ReportGenerator(errors, 'html', 'test_report')

        # 生成报告
        report_file_path = report_generator.generate()

        # 验证报告文件是否存在
        self.assertTrue(os.path.exists(report_file_path), "报告文件应该存在")

        # 读取报告文件内容
        with open(report_file_path, 'r') as file:
            report_content = file.read()

        # 验证报告内容是否包含预期的信息，可以根据实际情况进行修改
        self.assertIn('<title>Code Audit Report-源代码安全审计报告</title>', report_content, "报告标题应正确显示")
        self.assertIn('<p><span style=\'font-size: 20px;\'>文件路径:</span> test_file.py</p >\n', report_content, "文件路径应正确显示")
        self.assertIn('<p>漏洞位置: 10</p>\n', report_content, "漏洞位置应正确显示")
        self.assertIn('<p>漏洞风险: Syntax error</p >\n', report_content, "漏洞风险应正确显示")
        # 添加更多的验证...

if __name__ == "__main__":
    unittest.main()
