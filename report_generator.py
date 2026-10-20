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
        # 汇总漏洞数量
        total_errors = len(errors)
        # 计算不同等级的漏洞数量
        severity_counts = {
            '严重漏洞': sum(1 for error in errors if error['level'] == '严重'),
            '高危漏洞': sum(1 for error in errors if error['level'] == '高危'),
            '中危漏洞': sum(1 for error in errors if error['level'] == '中危'),
            '低危漏洞': sum(1 for error in errors if error['level'] == '低危')
        }

        # 设置不同等级漏洞在表格中的背景颜色
        severity_colors = {
            '严重漏洞': '#FF6347',  # 火砖红
            '高危漏洞': '#FFA500',  # 橙色
            '中危漏洞': '#FFFF00',  # 黄色
            '低危漏洞': '#90EE90'   # 淡绿色
        }

        # 生成 HTML 报告
        html_report = "<html>\n<head>\n<title>Code Audit Report-源代码安全审计报告</title>\n</head>\n<body>\n"

        # 添加 CSS 样式使标题居中和表格框
        html_report += "<style>"
        html_report += "h1 , h2 ,h3{ text-align: center; }"
        html_report += "table { width: 50%; margin: auto; border-collapse: collapse; background-color: #f2f2f2; }"
        html_report += "th, td { text-align: center; padding: 8px; border: 1px solid #dddddd; }"
        html_report += "#piechart { width: 70%; margin: auto; }"  # 设置饼状图的样式
        html_report += "#piechart-title { font-size: 14px; }"  # 设置饼状图标题的字体大小
        html_report += "</style>"
        html_report += "</head>\n<body>\n"

        # 添加标题
        html_report += f"<h1>源代码安全审计报告</h1>\n"

       # 添加漏洞信息
        html_report += f"<h2><span style='font-size: 20px;'>针对Python源码文件夹进行审计,本次审计过程中检测到存在安全漏洞共 {total_errors} 个,漏洞详细分类如下表:</span></h2>\n\n"

        # 添加漏洞数量汇总信息
        html_report += "<h2><span style='font-size: 14px;'>漏洞数量汇总表</span></h2>\n"
        html_report += "<table>"
        html_report += "<tr><th>漏洞等级</th><th>漏洞个数</th></tr>"
        for severity, count in severity_counts.items():
            html_report += f"<tr style='background-color:{severity_colors[severity]};'><td>{severity}</td><td>{count}</td></tr>"
        html_report += "</table>\n"

        # 添加饼状图容器，并设置样式使其左右居中显示
        html_report += "<div style='width: 800px; margin: auto;'>\n"
        html_report += "  <div id='piechart' style='width: 70%; margin: auto;'></div>\n"  # 设置饼状图的宽度并居中显示
        html_report += "</div>\n"

        # 添加饼状图的 JavaScript 代码
        html_report += "<script type='text/javascript' src='https://www.gstatic.com/charts/loader.js'></script>\n"
        html_report += "<script type='text/javascript'>"
        html_report += "google.charts.load('current', {'packages':['corechart']});\n"
        html_report += "google.charts.setOnLoadCallback(drawChart);\n"
        html_report += "function drawChart() {\n"
        html_report += "var data = google.visualization.arrayToDataTable([\n"
        html_report += "['漏洞等级', '漏洞个数'],\n"
        for severity, count in severity_counts.items():
            html_report += f"['{severity}', {count}],\n"
        html_report += "]);\n"
        html_report += "var options = {\n"
        html_report += "title: '漏洞等级占比',\n"
        html_report += "width: 800,  // 设置宽度为 800 像素\n"
        html_report += "height: 600, // 设置高度为 600 像素\n"
        html_report += "pieHole: 0.2,\n"
        html_report += "};\n"
        html_report += "var chart = new google.visualization.PieChart(document.getElementById('piechart'));\n"
        html_report += "chart.draw(data, options);\n"
        # 居中显示饼状图标题
        html_report += "document.getElementsByTagName('text')[0].setAttribute('text-anchor', 'middle');\n"  
        # 调整标题位置
        html_report += "document.getElementsByTagName('text')[0].setAttribute('x', '300');\n"  
        html_report += "}\n"
        html_report += "</script>\n"

        # 遍历每个漏洞信息并生成对应的表格
        for error in errors:
            html_report += "<h2><span style='font-size: 14px;'>漏洞详情表</span></h2>\n"  # 添加漏洞详情表的标题
            html_report += "<table>"
            html_report += "<tr><th>名称</th><th>详细信息</th></tr>"
            # 遍历每个漏洞的属性并添加到表格中
            for key, value in error.items():
                if key != 'rule':
                    html_report += f"<tr><td>{key}</td><td>{value}</td></tr>"
            html_report += "</table>"
            html_report += "<hr>\n"
            
            html_report += "<hr>\n"

        html_report += "</body>\n</html>"

        return html_report
        
    def write_to_file(self,file_path, content):
        with open(file_path, 'w') as file:
            file.write(content)
        #print(f"报告以保存至：{file_path}")