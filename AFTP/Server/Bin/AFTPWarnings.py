from typing import Optional

class AFTPWarnings(UserWarning):
    def __init__(self, warning: str) -> None:
        self.warning: str = warning

    def __str__(self) -> str:
        return self.emit(self.warning)

    @classmethod
    def emit(
        cls,
        warning: Optional[str] = "Unknown warning"
        ) -> str:
        Message: str = f"""Warning (AFTP):
    This warning is made by Zelabs, please consider to fix the warning.
    {str(cls).replace("<class '", "").replace("'>", ":")} {warning}"""
        return Message

class DebugMessageWarning(AFTPWarnings):
    pass