from random import randint
from .models import User, PasswordReset_keys
from django.shortcuts import get_object_or_404
from django.utils import timezone

import random
import string


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = "".join(random.choice(characters) for _ in range(length))
    return random_string


def ResetPassword_key(email: int):

    try:
        user = get_object_or_404(User, email=email)
    except User.DoesNotExist:
        return False

    unique_key = ""
    while True:
        unique_key = generate_random_string(12)
        if not PasswordReset_keys.objects.filter(key=unique_key).exists():
            break

    expriation = timezone.now() + timezone.timedelta(hours=1)
    PasswordReset_keys.objects.create(user=user, key=unique_key, exp=expriation)
    return unique_key, user.id
