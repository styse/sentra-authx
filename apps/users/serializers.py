from rest_framework import serializers
from .models import User, OTP


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = ('phone_number', 'email', 'password')
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(
            email=validated_data.get("email"),
            phone_number=validated_data.get("phone_number"),
            password=password
        )
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        phone_number = attrs.get('phone_number')
        email = attrs.get('email')
        password = attrs.get('password')
        
        if not phone_number and not email:
            raise serializers.ValidationError("Email or phone_number is required.")

        if email:
            user = User.objects.filter(email=email).first()
        else:
            user = User.objects.filter(phone_number=phone_number).first()

        if not user:
            raise serializers.ValidationError("User not found.")

        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password.")

        if not user.is_active:
            raise serializers.ValidationError("User is inactive.")
        
        attrs['user'] = user
        return attrs


class LoginResponseSerializer(serializers.Serializer):
    user = serializers.DictField()
    token = serializers.CharField()
    

class OTPRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(required=True)

    def validate_phone(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("User with this phone number does not exist.")
        return value


class OTPVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        phone = attrs['phone_number']
        code = attrs['code']

        try:
            otp = OTP.objects.filter(
                user__phone_number=phone,
                code=code,
                is_used=False
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp.is_expired():
            raise serializers.ValidationError("OTP expired.")

        attrs['otp_instance'] = otp
        return attrs
