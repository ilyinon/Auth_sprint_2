import base64
import json

import httpx
from config.settings import AUTH_API_LOGIN_URL
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

print("Before getting user")
User = get_user_model()


class CinemaBackend(BaseBackend):
    print("The step 1")
    url = AUTH_API_LOGIN_URL

    def authenticate(self, request, username=None, password=None):
        params = {"email": username, "password": password}
        print(f"AUTH_API_LOGIN_URL: {AUTH_API_LOGIN_URL}")
        with httpx.Client() as client:
            token_response = client.post(
                AUTH_API_LOGIN_URL,
                json=params,
            )
        print(f"token_response: {token_response}")

        if token_response.status_code == httpx.codes.OK:

            token_data = token_response.json()

            print(f"{token_data.get("access_token")}")
            data = decode_token(token_data.get("access_token"))
            print(data)
            is_staff = False
            if "admin" in data.get("roles"):
                is_staff = True
            user_data = {
                "email": username,
                "id": data.get("user_id"),
                "is_staff": is_staff,
                "is_active": True,
            }
            print(user_data)

            try:
                print("try to save user")
                # user = User.objects.get(**user_data)
                user, created = User.objects.update_or_create(**user_data)
                print("got user from object has been saved")
                user.save()
                # print("user has been saved")
            except Exception as e:
                print(f"exception: {e}")
                return None
            print(f"user is {user}")
            return user
        else:
            return None

    def get_user(self, user_id):
        print("try to get user")
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def decode_token(token: str) -> dict:
    encoded_payload = token.split(".")[1]
    data = json.loads(base64.b64decode(encoded_payload + "=="))
    return data
