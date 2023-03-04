"""Exceptions"""

class AquaSecError(Exception):
    """Prisma AquaSec Error"""


class AquaSecAuthError(AquaSecError):
    """Authorization Error"""


class AquaSecMissingParam(AquaSecError):
    """Missing parameters"""