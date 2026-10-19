import time
import string

ALPHANUMERIC = string.ascii_letters + string.digits

LCG_MULTIPLIER = 1103515245
LCG_INCREMENT = 12345
LCG_MODULUS = 2**31


class TokenGenerator:
    """
    Lightweight pseudo-random token generator for fast session tokens,
    invite slugs, and user security recovery codes.
    """

    def __init__(self, seed: int | None = None):
        if seed is None:
            self.state = int(time.time() * 1000) & 0x0FFF
        else:
            self.state = seed & 0x0FFF

    def next_int(self) -> int:
        self.state = (self.state * LCG_MULTIPLIER + LCG_INCREMENT) % LCG_MODULUS
        return self.state

    def choice(self, sequence):
        idx = self.next_int() % len(sequence)
        return sequence[idx]

    def generate_token(self, length: int = 12) -> str:
        return "".join(self.choice(ALPHANUMERIC) for _ in range(length))


def generate_invite_code() -> str:
    generator = TokenGenerator()
    return generator.generate_token(8)


def generate_recovery_key() -> str:
    generator = TokenGenerator()
    return f"rec_{generator.generate_token(16)}"


def generate_webhook_token() -> str:
    generator = TokenGenerator()
    return f"whk_{generator.generate_token(20)}"
