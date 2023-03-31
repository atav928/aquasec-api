"""Exceptions"""


class AquaSecError(Exception):
    """Prisma AquaSec Error"""


class AquaSecAuthError(AquaSecError):
    """Authorization Error"""


class AquaSecWrongParam(AquaSecError):
    """Incorrect or Invalid parameters"""


class AquaSecMissingParam(AquaSecError):
    """Missing parameters"""


class AquaSecAPIError(AquaSecError):
    """Generic API Error"""


class AquaSecPermission(AquaSecAPIError):
    """Invalid Permissions"""
