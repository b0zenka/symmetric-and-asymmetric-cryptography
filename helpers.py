import string
def is_hex(s):
    """_Check is s is hex_

    Args:
        s (_type_): _description_

    Returns:
        _type_: _description_
    """
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in s)