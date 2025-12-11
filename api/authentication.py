from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.contrib.auth.models import User
from .jwt_utils import decode_token

class CustomJWTAuthentication(BaseAuthentication):
    """Custom authentication class for Django REST Framework that validates
    JSON Web Tokens passed through the `Authorization` HTTP header.

    This class expects the header to have the format:
        Authorization: Bearer <access_token>

    If the token is valid and correctly signed, the method returns a tuple:
        (user_instance, token_payload_dict)

    This class follows DRF's authentication protocol:
    - Returning None means "authentication not attempted", and DRF tries
      the next authentication class (or raises 401 if none succeed).
    - Raising AuthenticationFailed means the request is invalid and should
      immediately return a 401 Unauthorized response.

    Attributes:
        keyword (str):
            The required keyword in the Authorization header.
            By default set to "Bearer", following standard JWT conventions.
    """
    keyword = "Bearer"
    
    def authenticate_header(self, request):
        return f'{self.keyword} realm="api"'
    
    def authenticate(self, request):
        """Attempt to authenticate the request using a JWT access token.

        Step-by-step logic:
        1. Read the `Authorization` header from the incoming HTTP request.
        2. Check that the header exists and has the correct format.
        3. Extract the token part after the "Bearer" keyword.
        4. Use `decode_token()` to verify the JWT signature, expiration time,
           and extract the payload.
        5. Confirm that the token type is "access", since refresh tokens
           must not be used for authentication.
        6. Attempt to find a User model instance using the user_id
           stored in the token payload.
        7. If everything is valid, return the Django user and the payload.

        Parameters:
            request (rest_framework.request.Request):
                The DRF request object containing headers, authentication data,
                and contextual information. The authentication method extracts
                the header using `request.headers.get("Authorization")`.

        Returns:
            tuple | None:
                - `(user, payload)` if authentication is successful.
                - `None` if the header is missing or has a different keyword,
                  allowing DRF to try the next authentication class.

        Raises:
            AuthenticationFailed:
                - The Authorization header format is invalid.
                - The JWT cannot be decoded (expired, bad signature, corrupted).
                - The token type is not "access".
                - The token payload does not contain `user_id`.
                - The user associated with the token does not exist.

        About decode_token():
            The function `decode_token()` is imported from jwt_utils and is
            responsible for verifying the signature, expiration time, and
            returning the payload as a Python dictionary. Any exceptions
            thrown inside that function will be converted into DRF's
            AuthenticationFailed exceptions inside this method.

        Why return (user, payload)?
            DRF requires authentication classes to return a tuple `(user, auth)`.
            We use the decoded payload as auth information so that views
            can optionally reuse token metadata (e.g. "iat", "type", "user_id").
        """
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None

        try:
            keyword, token = auth_header.split()
        except ValueError:
            raise exceptions.AuthenticationFailed("Invalid Authorization header format. Use 'Bearer <token>'.")

        if keyword != self.keyword:
            return None

        try:
            payload = decode_token(token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(str(e))

        if payload.get("type") != "access":
            raise exceptions.AuthenticationFailed("Invalid token type. Access token required.")

        user_id = payload.get("user_id")
        if not user_id:
            raise exceptions.AuthenticationFailed("Invalid payload: user_id missing.")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found.")

        return (user, payload)