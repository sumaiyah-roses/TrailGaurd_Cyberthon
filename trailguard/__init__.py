"""TrailGuard: an explainable account-takeover detector."""
from .pipeline import analyze, load_logs
from .config import VARIANTS

__all__ = ["analyze", "load_logs", "VARIANTS"]
