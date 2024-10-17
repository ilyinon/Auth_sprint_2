import requests
from django.conf import settings
from django.http import HttpResponseForbidden


class RoleCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get("Authorization")
        if not self.check_user_role(token, ["admin"]):
            return HttpResponseForbidden(
                "You are not authorized to access this resource"
            )

        response = self.get_response(request)
        return response

    def check_user_role(self, token: str, required_roles: list) -> bool:
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            params = {"allow_roles": ",".join(required_roles)}

            try:
                response = requests.get(
                    settings.AUTH_SERVER_URL, headers=headers, params=params
                )
                if response.status_code == 200:
                    return True
            except requests.RequestException as e:
                print(f"Error connecting to auth server: {e}")
        return False
