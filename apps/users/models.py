from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email=None, phone_number=None, password=None, **extra_fields):
        if not email and not phone_number:
            raise ValueError("A user must have either an email or phone number.")

        if email:
            email = self.normalize_email(email)

        user = self.model(
            email=email,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email=email, password=password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email or self.phone_number or str(self.id)



def default_otp_expiry():
    return timezone.now() + timedelta(minutes=5)


class OTP(models.Model):

    class Purpose(models.TextChoices):
        LOGIN = "login", "Login"
        REGISTER = "register", "Register"
        PASSWORD_RESET = "password_reset", "Password Reset"
        PHONE_VERIFICATION = "phone_verification", "Phone Verification"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="otps",
    )

    code_hash = models.CharField(max_length=128, default="")

    purpose = models.CharField(
        max_length=30,
        choices=Purpose.choices,
        default=Purpose.LOGIN,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    expires_at = models.DateTimeField(default=default_otp_expiry)

    attempts = models.PositiveSmallIntegerField(default=0)

    max_attempts = models.PositiveSmallIntegerField(default=5)

    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["user", "purpose", "created_at"],
                name="otp_user_purpose_idx",
            ),
        ]

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def is_consumed(self):
        return self.consumed_at is not None

    def has_exceeded_attempts(self):
        return self.attempts >= self.max_attempts

    def __str__(self):
        return f"OTP ({self.purpose}) for {self.user}"
