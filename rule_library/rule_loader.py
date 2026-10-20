# rule_loader.py

import os
import importlib
import inspect
from rule_library import Rule

def load_rules():
    rule_files = os.listdir("rule_library")
    rules = []
    for file in rule_files:
        if file.endswith(".py") and file != "__init__.py":
            module_name = os.path.splitext(file)[0]
            module = importlib.import_module(f"rule_library.{module_name}")
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, Rule) and obj != Rule:
                    rules.append(obj())
    return rules
