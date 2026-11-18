
import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.users.models import OTP


class OTPService:

    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 5

    MAX_SEND_ATTEMPTS = 5
    SEND_WINDOW_SECONDS = 3600

    @staticmethod
    def generate_code():
        return f"{secrets.randbelow(10 ** OTPService.OTP_LENGTH):06d}"

    @staticmethod
    def hash_code(code):
        return hashlib.sha256(
            f"{settings.SECRET_KEY}:{code}".encode()
        ).hexdigest()

    @staticmethod
    def get_send_limit_key(phone_number, purpose):
        return f"otp:send:{purpose}:{phone_number}"

    @classmethod
    def can_send_otp(cls, phone_number, purpose):
        key = cls.get_send_limit_key(phone_number, purpose)
        attempts = cache.get(key, 0)

        return attempts < cls.MAX_SEND_ATTEMPTS

    @classmethod
    def mark_send_attempt(cls, phone_number, purpose):
        key = cls.get_send_limit_key(phone_number, purpose)

        try:
            cache.add(key, 0, timeout=cls.SEND_WINDOW_SECONDS)
            cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=cls.SEND_WINDOW_SECONDS)

    @classmethod
    def create_otp(cls, user, purpose):
        if not cls.can_send_otp(user.phone_number, purpose):
            raise ValueError("Too many OTP requests. Try again later.")

        code = cls.generate_code()

        otp = OTP.objects.create(
            user=user,
            code_hash=cls.hash_code(code),
            purpose=purpose,
            expires_at=timezone.now() + timedelta(
                minutes=cls.OTP_EXPIRY_MINUTES
            ),
        )

        cls.mark_send_attempt(user.phone_number, purpose)

        return otp, code

    @classmethod
    def verify_otp(cls, user, code, purpose):
        with transaction.atomic():
            otp = (
                OTP.objects
                .select_for_update()
                .filter(
                    user=user,
                    purpose=purpose,
                    consumed_at__isnull=True,
                )
                .order_by("-created_at")
                .first()
            )

            if otp is None:
                raise ValueError("Invalid or expired OTP.")

            if otp.is_expired():
                raise ValueError("Invalid or expired OTP.")

            if otp.has_exceeded_attempts():
                raise ValueError("Maximum OTP attempts exceeded.")

            otp.attempts += 1

            if otp.code_hash != cls.hash_code(code):
                otp.save(update_fields=["attempts"])
                raise ValueError("Invalid or expired OTP.")

            otp.consumed_at = timezone.now()

            otp.save(update_fields=["attempts", "consumed_at"])

            return otp
