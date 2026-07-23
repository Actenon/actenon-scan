def internal_write(path, content):
    with open(path, "w") as f:
        f.write(content)
