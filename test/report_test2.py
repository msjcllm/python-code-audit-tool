import unittest
from report_generator import ReportGenerator

class TestReportFormatting(unittest.TestCase):
    def test_html_report_format(self):
        # 准备测试数据，假设有一个包含错误信息的列表
        errors = [
            {
                'file': 'test_file.py',
                'line': 10,
                'error': '漏洞描述',
                'code': '漏洞代码示例',
                'CWE': 'CWE-123',
                'CVSS': 7.5,
                'rule': None,  # 假设没有规则对象
            }
        ]
        
        # 创建报告生成器对象
        report_generator = ReportGenerator(errors, 'html', 'test_report')

        # 生成报告
        html_report = report_generator.generate_html_report(errors)

        # 验证生成的报告是否包含HTML标签
        self.assertIn("<html>", html_report)
        self.assertIn("</html>", html_report)
        self.assertIn("<body>", html_report)
        self.assertIn("</body>", html_report)
        self.assertIn("<title>", html_report)
        self.assertIn("</title>", html_report)
        self.assertIn("<p>", html_report)
        self.assertIn("</p>", html_report)
        self.assertIn("<hr>", html_report)

if __name__ == "__main__":
    unittest.main()
