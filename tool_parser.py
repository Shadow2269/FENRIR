"""
tool_parser.py
Extracts structured TOOL / TARGET directives from AI responses.
"""


def parse_tool(response: str) -> tuple[str | None, str | None]:
    """
    Look for lines of the form:
        TOOL: <tool_name>
        TARGET: <ip_or_host>

    Returns:
        (tool, target) — both None if no directive found.
    """
    if "TOOL:" not in response:
        return None, None

    tool: str | None = None
    target: str | None = None

    for line in response.splitlines():
        stripped = line.strip()
        if stripped.startswith("TOOL:"):
            tool = stripped[len("TOOL:"):].strip().lower()
        elif stripped.startswith("TARGET:"):
            target = stripped[len("TARGET:"):].strip()

    return tool, target
