from fastmcp import FastMCP

from vulnmcp.models.classifier import AttackTechniqueClassifier

INSTRUCTIONS = (
    "Use classify_attack_techniques to predict MITRE ATT&CK techniques "
    "from a vulnerability description."
)

_classifier = AttackTechniqueClassifier()


def classify_attack_techniques(
    description: str, title: str = "", top_k: int = 10
) -> dict:
    """Predict MITRE ATT&CK (Enterprise) techniques for a vulnerability.

    Uses CIRCL's fine-tuned RoBERTa-base multi-label model, trained on a
    curated gold set of CVE-to-technique mappings. Every technique in the
    model's vocabulary is scored independently (sigmoid); scores at or
    above 0.5 are the model's positive predictions, and the rest of the
    ranking shows how it orders the remaining candidates.

    Args:
        description: The vulnerability description text.
        title: Optional vulnerability title, prepended to the description
               exactly as during training.
        top_k: Number of ranked techniques to return (default 10).

    Returns:
        A dict with: predicted_techniques (technique IDs scoring >= 0.5),
        techniques (top_k ranked entries with technique ID, name, score,
        and predicted flag), and model.
    """
    return _classifier.classify(description, title=title, top_k=top_k)


def register(mcp: FastMCP) -> None:
    """Register ATT&CK technique classification tools on the MCP server."""
    mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )(classify_attack_techniques)
