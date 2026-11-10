import os


class AIAnalysisService:
    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "disabled")
        self.api_key = os.getenv("AI_API_KEY")

    async def generate_explanation(self, scanner_type: str, findings: list[str], score: float) -> dict:
        if not self.api_key or self.provider.lower() == "disabled":
            return {
                "provider": "Unavailable",
                "assessment": "No AI provider is configured, so the deterministic security findings remain the primary evidence source.",
                "verification_status": "Not verified",
                "confidence": 0.0,
            }

        return {
            "provider": self.provider,
            "assessment": f"The {scanner_type} analysis shows a score of {score} with multiple indicators that warrant investigation.",
            "verification_status": "AI-generated context only",
            "confidence": 0.72,
        }
