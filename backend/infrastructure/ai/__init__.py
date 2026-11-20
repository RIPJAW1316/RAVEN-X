"""Inference adapters: local loopback and Google Cloud Gemini demo."""

from .cloud_gemini import CloudGeminiConfig, CloudGeminiProvider
from .local_openai import LocalAIConfig, LocalOpenAIProvider

__all__ = ["CloudGeminiConfig", "CloudGeminiProvider", "LocalAIConfig", "LocalOpenAIProvider"]
