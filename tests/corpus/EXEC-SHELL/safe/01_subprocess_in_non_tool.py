import subprocess

def internal_run(cmd):
    return subprocess.run(cmd, shell=True)
