from fastmcp import FastMCP

from vulnmcp.models.classifier import SeverityClassifier


def register(mcp: FastMCP) -> None:
    """Register severity classification tools on the MCP server."""

    classifier = SeverityClassifier()

    @mcp.tool
    def classify_severity(
        description: str, language: str | None = None
    ) -> dict:
        """Classify the severity of a vulnerability based on its description.

        Uses CIRCL's fine-tuned transformer models:
        - English descriptions: RoBERTa-based model (low/medium/high/critical)
        - Chinese descriptions: MacBERT-based model (low/medium/high)

        Language is auto-detected from the text unless explicitly specified.

        Args:
            description: The vulnerability description text (English or Chinese).
            language: Optional language hint — "en" for English, "zh" for Chinese.
                      Auto-detected if omitted.

        Returns:
            A dict with: label (severity), score (confidence), model, language.
        """
        return classifier.classify(description, language=language)
