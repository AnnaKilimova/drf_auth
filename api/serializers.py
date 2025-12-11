from rest_framework import serializers
from django.contrib.auth.models import User

class LoginSerializer(serializers.Serializer):
    """This class is used for:
    - validating the data sent by the client during login,
    - converting the data into the appropriate Python types,
    - restricting which fields can be read or written.

    Main features:
        - username: a required text field (CharField), representing the username.
        - password: a required text field (CharField) with write_only=True,
                    so that the password is not returned to the client in responses.

    Note:
        serializers.Serializer is the base DRF serializer used for manually
        describing fields. Unlike serializers.ModelSerializer, here we explicitly
        define fields and their properties without binding directly to the User model.

    Attributes:
        username (CharField):
            - Type: str
            - Description: username
            - Required field
            - Automatically validated by DRF for presence and string length

        password (CharField):
            - Type: str
            - Description: user password
            - Required field
            - write_only=True → the field is used only for writing (when receiving data)
            and will not be returned in DRF’s serialized responses
    """
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)