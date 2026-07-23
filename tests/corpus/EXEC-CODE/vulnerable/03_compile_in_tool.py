from crewai import Tool

@Tool("Compiler", "Compiles code")
def compile_code(source: str) -> str:
    """Compile source code."""
    code = compile(source, "<agent>", "exec")
    exec(code)
    return "compiled"
