# r12: same-class multi-hop resolution — BaseTool._execute calls self.a() calls self.b() which has a sink.
# Real source: TransformerOptimus/SuperAGI @ c3c1982e7bd6a11cfed53c5a193ea502f924b1b6
#               superagi/tools/apollo/apollo_search.py:127
# Pattern: ApolloSearchTool(BaseTool)._execute -> self.apollo_search_results() -> requests.post :127
# Expected: >=1 finding (same_class_method signal, MEDIUM confidence, 2 hops)

from crewai_tools.tools.base_tool import BaseTool
import requests


class ApolloSearchTool(BaseTool):
    def _execute(self, query: str) -> str:
        """Agent-reachable entrypoint — _execute is a tool_base_class_method."""
        return self.apollo_search_results(query)

    def apollo_search_results(self, query: str) -> str:
        """Same-class method called from _execute. Makes an external
        request with agent-controlled input."""
        # The sink — agent-controlled query flows to requests.post
        response = requests.post(
            "https://api.apollo.io/v1/mixed_people/search",
            data={"q": query},
        )
        return response.text
