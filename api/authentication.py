import hashlib
from rest_framework import authentication
from rest_framework import exceptions
from .models import UserSessions, Users
from django.utils import timezone

class LegacyTokenAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            # Expecting "Bearer <token>"
            token_type, token = auth_header.split()
            if token_type.lower() != 'bearer':
                return None
        except ValueError:
            return None

        # Hash the token to match DB storage
        # Assuming SHA256 for now, need to verify with existing auth system if any
        # For this implementation, we'll assume the token passed IS the hash or we hash it.
        # Given 'access_token_hash', we likely need to hash.
        # Let's assume simple SHA256 hex digest for now.
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        try:
            session = UserSessions.objects.get(
                access_token_hash=token_hash,
                is_active=True,
                expires_at__gt=timezone.now()
            )
        except UserSessions.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid or expired token')

        return (session.user, session)
