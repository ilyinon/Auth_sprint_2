import random
import string


def generate_string(length=32):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(length)
    )
