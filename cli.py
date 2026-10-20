# coding:utf-8

import logging
import sys
import os

from tqdm import tqdm
from code_parser import CodeParser
from report_generator import ReportGenerator
from rule_engine import RuleEngine
from rule_library import load_rules


def main():
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 2:
        # py-code为需审计的文件夹
        print(f"用法: python -m cli '审计源码的文件路径'")
        sys.exit(1)


    logging.info("创建规则库...")
    rules = load_rules()
    

    logging.info("创建规则执行引擎...")
    engine = RuleEngine(rules)
    

    logging.info("开始解析和审计代码...")
    try:

        parser = CodeParser(sys.argv[1])
        # 获取总文件数
        total_files = sum(1 for _ in parser.trees)
        # 初始化进度条
        with tqdm(total=total_files, desc="审计进度") as pbar:
            # 存储所有文件的错误信息
            errors = [] 
            result_folder = 'result'
            if not os.path.exists(result_folder):
                os.makedirs(result_folder)
            output_file_path = os.path.join(result_folder, "output.txt")
            with open(output_file_path, "w") as output_file:
                # 遍历每个文件进行处理
                for file_path, tree in parser.trees:
                    # 更新进度条
                    pbar.update(1)  
                    # 处理当前文件
                    engine.process_file(file_path, tree)
                    for error in engine.errors:
                        if error not in errors:
                            errors.append(error)
                        output_file.write(f"File: {error['File']}\n")
                        output_file.write(f"Line: {error['Line']}\n")
                        output_file.write(f"Error: {error['Error']}\n")
                        output_file.write(f"Code: {error['Code']}\n")
                        # 存储规则对象
                        output_file.write(f"Rule: {error['RuleName']}\n")
                        output_file.write(f"XiangQing:{error['XiangQing']}\n")
                        output_file.write(f"Level: {error['level']}\n")
                        output_file.write(f"Suggestion: {error['Suggestion']}\n")
                        output_file.write(f"CWE: {error['CWE']}\n")
                        output_file.write(f"CVSS: {error['CVSS']}\n\n")

        # 生成报告
        logging.info("生成报告...")
        reports = ReportGenerator(errors, "html", "code_report.html")
        result_file_path = reports.generate()
        print(f"审计报告已保存至：{result_file_path}")

        logging.info("完成代码审计。")

    except Exception as e:
        logging.error(f"在代码审计过程中出错: {e}")
        sys.exit(1)



if __name__ == '__main__':
    main()
