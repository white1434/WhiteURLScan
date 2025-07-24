import os
import sys
import re

class OutputLogger:
    def __init__(self, log_file="results/output.out"):
        self.log_file = log_file
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.log_stream = open(log_file, 'a', encoding='utf-8')
    def write(self, text):
        self.original_stdout.write(text)
        try:
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', text)
            self.log_stream.write(clean_text)
            self.log_stream.flush()
        except Exception:
            pass
    def flush(self):
        self.original_stdout.flush()
        try:
            self.log_stream.flush()
        except Exception:
            pass
    def close(self):
        try:
            self.log_stream.close()
        except Exception:
            pass 