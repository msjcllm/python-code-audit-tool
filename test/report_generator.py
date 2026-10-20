# coding:utf-8

import os
from datetime import datetime


class ReportGenerator:
    def __init__(self,errors,output_format,file_path):
        self.errors = errors
        self.output_format = output_format
        self.file_path = file_path

    def generate(self):
        if self.output_format == 'html':
            html_report = self.generate_html_report(self.errors)
            # 创建 result 文件夹
            result_folder = 'result' 
            if not os.path.exists(result_folder):
                os.makedirs(result_folder)

            # 添加时间戳到文件名中
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  
            # 动态构建完整的文件路径、文件名
            result_file_path = os.path.join(result_folder, f"{self.file_path}_{timestamp}.html")   
            self.write_to_file(result_file_path, html_report)
            return result_file_path

        else:
            return "Unsupported output format"

    def generate_html_report(self, errors):
        #html_report = "<html>\n<body>\n"
        html_report = "<html>\n<head>\n<title>Code Audit Report-源代码安全审计报告</title>\n</head>\n<body>\n"

        for error in errors:
            # 遍历风险信息并打印
            html_report += f"<p><span style='font-size: 20px;'>文件路径:</span> {error['file']}</p >\n"
            html_report += f"<p>漏洞位置: {error['line']}</p>\n"
            html_report += f"<p>漏洞风险: {error['error']}</p >\n"
            html_report += f"<p>风险代码: {error['code']}</p >\n"

            # 如果存在相关信息，则添加到报告中
            html_report += f"<p>CWE分类: {error['CWE']}</p>\n"
            html_report += f"<p>CVSS评分: {error['CVSS']}</p>\n"

            # 添加漏洞修复建议
            # 添加漏洞修复建议
            rule = error.get('rule', None)
            if rule and hasattr(rule, 'get_fix_suggestion'):  
                fix_suggestion = rule.get_fix_suggestion()
            else:
                fix_suggestion = "暂无修复建议"  
            html_report += f"<p>漏洞修复建议: {fix_suggestion}</p>\n\n"
            
            html_report += "<hr>\n"
        html_report += "</body>\n</html>"

        return html_report
        
    def write_to_file(self,file_path, content):
        with open(file_path, 'w') as file:
            file.write(content)
        #print(f"报告以保存至：{file_path}")