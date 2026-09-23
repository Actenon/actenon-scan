# LLM output flows to eval() — mechanism LLM_OUTPUT_TO_SINK (CVE-2024-21552 shape)
# Expected: finding (the sink IS detected by EXEC-CODE rule)
# But: the scanner does NOT connect it to an agent boundary.
# This is a NOT COVERED mechanism — LLM_OUTPUT_TO_SINK.
# See docs/COVERAGE.md "LLM output reaching a sink" section.
# Motivating example: CVE-2024-21552 in SuperAGI (superagi/agent/output_handler.py:180).

def handle(self, session, assistant_reply):
    # assistant_reply is the LLM's raw text output
    tasks = eval(assistant_reply)  # eval() on raw model output — RCE
    return tasks
