from django.urls import path
from .views import TokenObtainView, TokenRefreshView, ProtectedView

urlpatterns = [
    path("token/", TokenObtainView.as_view(), name="token_obtain"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("protected/", ProtectedView.as_view(), name="protected"),
]
