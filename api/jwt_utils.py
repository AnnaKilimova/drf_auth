import jwt
from datetime import datetime, timedelta
from django.conf import settings

JWT_SETTINGS = getattr(settings, "JWT", {})
ALGORITHM = JWT_SETTINGS.get("ALGORITHM", "HS256")
ACCESS_MIN = JWT_SETTINGS.get("ACCESS_TOKEN_LIFETIME_MINUTES", 5)
REFRESH_DAYS = JWT_SETTINGS.get("REFRESH_TOKEN_LIFETIME_DAYS", 7)
SECRET_KEY = settings.SECRET_KEY

def generate_access_token(user):
    """Generate a short-lived access JWT for a given user.

    This token contains:
    - user_id: The ID of the authenticated user.
    - exp: Unix timestamp representing the expiration moment.
    - type: A custom field set to "access" to distinguish token types.
    - iat: The "issued at" time (UTC).

    The token is signed using the project's Django SECRET_KEY and the algorithm
    defined in the JWT settings.

    Parameters:
        user (django.contrib.auth.models.User):
            A Django User instance. The function expects the user to have an "id" attribute.

    Returns:
        str:
            A signed JWT string. If the underlying PyJWT version returns bytes,
            the value is decoded to UTF-8 for consistency.
    """
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_MIN)
    payload = {
        "user_id": user.id,
        "exp": exp,
        "type": "access",
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def generate_refresh_token(user):
    """Generate a long-lived refresh JWT for a given user.

    A refresh token is used to obtain new access tokens without requiring
    the user to log in again. It has a longer lifetime (in days) than
    an access token and contains similar claims:

    - user_id: The ID of the authenticated user.
    - exp: Expiration timestamp (UTC).
    - type: "refresh", used to identify the token type.
    - iat: Issue time (UTC).

    Parameters:
        user (django.contrib.auth.models.User):
            A Django User instance with an "id" attribute.

    Returns:
        str:
            A signed JWT refresh token, always returned as a UTF-8 string.
    """
    exp = datetime.utcnow() + timedelta(days=REFRESH_DAYS)
    payload = {
        "user_id": user.id,
        "exp": exp,
        "type": "refresh",
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token
    
def decode_token(token):
    """Decode and validate a JWT token.

    This function performs:
    - Signature verification using SECRET_KEY.
    - Algorithm validation using the configured ALGORITHM.
    - Expiration validation (raises an exception if the token is expired).
    - Payload extraction into a Python dictionary.

    The function does not suppress JWT errors. Instead, it re-raises them so that
    higher-level code (e.g., authentication middleware or API views) can decide
    how to handle invalid or expired tokens.

    Parameters:
        token (str):
            The JWT token string to be decoded and validated.

    Returns:
        dict:
            A dictionary containing the decoded JWT payload if the token is valid.

    Raises:
        jwt.ExpiredSignatureError:
            Raised when the token's expiration time has passed.

        jwt.InvalidTokenError:
            Raised when the token is malformed, tampered with, signed incorrectly,
            or fails any validation check.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError:
        raise
        