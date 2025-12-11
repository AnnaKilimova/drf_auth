from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.contrib.auth import authenticate
from .serializers import LoginSerializer
from .jwt_utils import generate_access_token, generate_refresh_token, decode_token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated


class TokenObtainView(APIView):
    """Endpoint for obtaining an access/refresh token pair using username and password."""
    permission_classes = (AllowAny, )
    
    def post(self, request):
        """
        1. Validate input via LoginSerializer (400 returned automatically on error).
        2. Authenticate user using Django's `authenticate()`.
           - If authentication fails → return 401 Unauthorized.
        3. Generate:
           - access token via `generate_access_token(user)`
           - refresh token via `generate_refresh_token(user)`
        4. Return both tokens in JSON.

        Returns:
            200 OK with {"access": ..., "refresh": ...}
            400 Bad Request if validation fails
            401 Unauthorized if credentials are invalid

        Notes:
        - Should be used over HTTPS only.
        - Do not log passwords or tokens.
        - Rate limiting is recommended to reduce brute-force risk.
        """
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            
        access = generate_access_token(user)
        refresh = generate_refresh_token(user)
        return Response({"access": access, "refresh": refresh})
        
class TokenRefreshView(APIView):
    """Endpoint for generating a new access token by using a valid refresh token."""
    permission_classes = (AllowAny, )
    
    def post(self,request):
        """
        1. Ensure "refresh" is present in request body (else 400).
        2. Decode and validate the refresh token via `decode_token()`.
           - On decode error → return 401 Unauthorized.
        3. Verify token type is "refresh" (else 400).
        4. Extract user_id from payload and ensure user exists (404 otherwise).
        5. Issue a new access token and return it.

        Returns:
            200 OK with {"access": "<new_access_token>"}
            400 Bad Request if token type is invalid or "refresh" missing
            401 Unauthorized if token is invalid/expired
            404 Not Found if user doesn’t exist

        Security notes:
        - Refresh tokens must be transmitted only over HTTPS.
        - Production systems often store issued refresh tokens for revocation support.
        """
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
        try: 
            payload = decode_token(refresh_token)
        except Exception as e:
            return Response({"detail": "Invalid refresh token: " + str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        if payload.get("type") != "refresh":
            return Response({"detail": "Token is not refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = payload.get("user_id")
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        access = generate_access_token(user)
        return Response({"access": access})
    
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
    
    """Example of a protected endpoint that requires a valid access token."""
    def get(self, request):
        """
        Requirements:
        - Must include a valid JWT access token in:
              Authorization: Bearer <access_token>

        Behavior:
        - If token is valid, `request.user` is populated with the authenticated user.
        - Returns a personalized message.

        Returns:
            200 OK with a greeting
            401 Unauthorized if authentication fails
        """
        user = request.user
        return Response({"message": f"Hello, {user.username}! This is protected data."})
    
    
    


