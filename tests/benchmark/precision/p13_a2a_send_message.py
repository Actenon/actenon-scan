"""Regression fixture: agno cookbook/05_agent_os/15_a2a/.../trip_planning_a2a_client.py:53.

`weather_client.send_message(request)` where weather_client is an A2AClient.
This is inter-agent transport — one agent handing a task to another — not a
consequential side effect on the outside world. It is the dominant category
in the recorded r05 negative result (framework message-passing plumbing).

A real Slack/email send on a genuine channel must still fire; see the
superagi slack/email true positives in corpus-triage.json.

Expected findings: 0
"""

import asyncio

from agno.agent import Agent
from agno.client.a2a import A2AClient, TaskResult

weather_client = A2AClient(base_url="http://127.0.0.1:7782")


async def ask_weather_agent(request: str) -> str:
    """Ask the weather specialist through A2A."""
    result = await weather_client.send_message(request)
    return result.content


agent = Agent(name="Trip Planner", tools=[ask_weather_agent])
