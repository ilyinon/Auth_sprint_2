import random
import string


def generate_password(length=12):

    lowercase = string.ascii_lowercase
    characters = lowercase

    characters += string.digits
    characters += string.ascii_uppercase
    characters += string.punctuation

    password = "".join(random.choice(characters) for _ in range(length))
    return password
