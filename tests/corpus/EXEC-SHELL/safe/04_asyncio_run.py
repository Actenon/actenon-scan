import asyncio
from langchain.tools import tool

@tool
def run_async_task() -> str:
    """asyncio.run() is the event loop runner, NOT shell execution."""
    async def main():
        await asyncio.sleep(0.1)
    asyncio.run(main())
    return "done"
