from fastmcp import FastMCP

from vulnmcp.models.classifier import CWEClassifier, SeverityClassifier


def register(mcp: FastMCP) -> None:
    """Register ML classification tools on the MCP server."""

    severity_classifier = SeverityClassifier()
    cwe_classifier = CWEClassifier()

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
    def classify_severity(
        description: str, language: str | None = None
    ) -> dict:
        """Classify the severity of a vulnerability based on its description.

        Uses CIRCL's fine-tuned transformer models:
        - English descriptions: RoBERTa-base model (low/medium/high/critical)
        - Chinese descriptions: MacBERT-base model (low/medium/high)
        - Russian descriptions: ruRoBERTa-large model (low/medium/high/critical)

        Language is auto-detected from the text unless explicitly specified.

        Args:
            description: The vulnerability description text (English, Chinese, or Russian).
            language: Optional language hint — "en" for English, "zh" for Chinese,
                      "ru" for Russian. Auto-detected if omitted.

        Returns:
            A dict with: label (severity), score (confidence), model, language.
        """
        return severity_classifier.classify(description, language=language)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
    def classify_cwe(description: str) -> dict:
        """Classify a vulnerability description into CWE categories.

        Uses CIRCL's fine-tuned RoBERTa model to predict the most likely
        CWE (Common Weakness Enumeration) categories, mapped to their
        parent CWEs.

        Args:
            description: The vulnerability description text (English).

        Returns:
            A dict with: primary_cwe, confidence, predictions (top 5), model.
        """
        return cwe_classifier.classify(description)
