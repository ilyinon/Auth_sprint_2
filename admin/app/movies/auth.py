import base64
import json
from typing import Any, Dict

import httpx
from config.settings import AUTH_API_LOGIN_URL
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

User = get_user_model()


class CinemaBackend(BaseBackend):
    url = AUTH_API_LOGIN_URL

    def authenticate(self, request, username=None, password=None):
        params = {"email": username, "password": password}
        with httpx.Client() as client:
            token_response = client.post(
                AUTH_API_LOGIN_URL,
                json=params,
            )

        if token_response.status_code == httpx.codes.OK:
            try:
                token_data = token_response.json()
            except:
                return None

            data = decode_token(token_data.get("access_token"))
            is_staff = False
            if "admin" in data.get("roles"):
                is_staff = True
            user_data = {
                "email": username,
                "id": data.get("user_id"),
                "is_staff": is_staff,
                "is_active": True,
            }

            try:
                # user = User.objects.get(**user_data)
                user, created = User.objects.update_or_create(**user_data)
                user.save()
            except Exception as e:
                return None
            return user
        else:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def decode_token(token: str) -> dict[str, Any]:
    try:
        # Get the part with token
        encoded_payload = token.split(".")[1]
        # Add bytes for correct decoding
        decoded_bytes = base64.b64decode(encoded_payload + "==")
        data = json.loads(decoded_bytes)
        return data
    except (IndexError, ValueError) as e:
        raise ValueError("Token wrong format") from e
    except json.JSONDecodeError as e:
        raise ValueError("Erorr during JSON decoding") from e
