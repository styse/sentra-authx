from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import generics
from knox.models import AuthToken
from knox.views import LogoutView as KnoxLogoutView
from knox.views import LogoutAllView as KnoxLogoutAllView
from knox.auth import TokenAuthentication
from django.utils import timezone
from .models import OTP, User
from .serializers import (
    UserRegisterSerializer, UserLoginSerializer,
    OTPRequestSerializer, OTPVerifySerializer,
    LoginResponseSerializer
)
from apps.user_sessions.services import (
    deactivate_session_by_token_key,
    deactivate_all_sessions_for_user,
    create_user_session
)
from drf_spectacular.utils import extend_schema, OpenApiExample
import random


@extend_schema(
    tags=["Authentication"],
    examples=[
        OpenApiExample(
            "Register Example",
            value={"email": "styse011@gmail.com", "phone_number": "+49123456789", "password": "yOurp1471@ssw0rd"},
        )
    ],
    request=UserRegisterSerializer,
    summary="User Register with email/phone and password",
    responses={200: LoginResponseSerializer},
)
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        token = AuthToken.objects.create(user)[1]

        return Response({
            "user": {
                "id": user.id,
                "email": user.email,
                "phone_number": user.phone_number,
            },
            "token": token
        }, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["Authentication"],
    examples=[
        OpenApiExample(
            "Login Example",
            value={"email": "styse011@gmail.com", "phone_number": "+49123456789", "password": "yOurp1471@ssw0rd"},
        )
    ],
    request=UserLoginSerializer,
    summary="User login with email/phone and password",
    responses={200: LoginResponseSerializer},
)
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            auth_token, token = AuthToken.objects.create(user)

            create_user_session(user, token, request)
            
            return Response({"token": token}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    tags=["Authentication"],
    summary="User logout from current device",
    responses={200: {"description": "Logged out successfully"}},
)
class LogoutView(KnoxLogoutView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, format=None):
        token_key = request.auth
        if token_key:
            deactivate_session_by_token_key(token_key)
        
        return Response({"detail": "Logged out successfully",}, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Authentication"],
    summary="User logout from all devices",
    responses={200: {"description": "Logged out from all devices"}},
)
class LogoutAllView(KnoxLogoutAllView):
    
    def post(self, request, format=None):
        user = request.user
        
        deactivate_all_sessions_for_user(user)
        
        super().post(request, format=format)
        
        return Response({"detail": "Logged out from all devices"}, status=200)
    

class RequestOTPView(generics.GenericAPIView):
    serializer_class = OTPRequestSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phone_number']
        user = User.objects.get(phone_number=phone_number)

        # Generate OTP
        code = str(random.randint(100000, 999999))
        OTP.objects.create(
            user=user,
            code=code,
            expires_at=timezone.now() + timezone.timedelta(minutes=5)
        )

        # TODO: Send OTP via SMS provider
        print(f"OTP for {phone_number}: {code}")

        return Response({"detail": "OTP sent successfully"}, status=status.HTTP_200_OK)


@extend_schema(
    tags=["OTP Authentication"],
    request=OTPVerifySerializer,
    examples=[
        OpenApiExample(
            "Verify OTP Example",
            value={"phone_number": "+49123456789", "code": "123456"},
        )
    ],
)
class VerifyOTPView(generics.GenericAPIView):
    serializer_class = OTPVerifySerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp_instance = serializer.validated_data['otp_instance']
        otp_instance.is_used = True
        otp_instance.save()

        token_key = AuthToken.objects.create(otp_instance.user)[1]
        create_user_session(otp_instance.user, token_key, request)

        return Response({
            "user": {
                "id": otp_instance.user.id,
                "phone_number": otp_instance.user.phone_number,
                "email": otp_instance.user.email,
            },
            "token": token_key
        }, status=status.HTTP_200_OK)
