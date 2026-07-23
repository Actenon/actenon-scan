from pathlib import Path

def internal_write(path, content):
    Path(path).write_text(content)
