from fastmcp import FastMCP

from vulnmcp.skills import attack, cwe, gcve, severity, vulnerability_lookup

SKILLS = [severity, cwe, attack, vulnerability_lookup, gcve]

mcp = FastMCP(
    name="VulnMCP",
    instructions=" ".join(
        ["VulnMCP provides AI-driven vulnerability management tools."]
        + [skill.INSTRUCTIONS for skill in SKILLS]
    ),
)

for skill in SKILLS:
    skill.register(mcp)


def main() -> None:
    mcp.run()
