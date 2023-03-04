"""Utilities"""



def set_bool(value: str, default: bool = False) -> bool:
    """sets bool value when pulling string from os env

    Args:
        value (str|bool, Required): the value to evaluate
        default (bool): default return bool value. Default False

    Returns:
        (str|bool): String if certificate path is passed otherwise True|False
    """
    value_bool: bool = default
    if isinstance(value, bool):
        value_bool = value
    elif str(value).lower() == 'true':
        value_bool: bool = True
    elif str(value).lower() == 'false':
        value_bool: bool = False
    else:
        value_bool: bool = False
    return value_bool



