from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.utils import timezone
import uuid
import hashlib

from .models import (
    Users, AuditLogs, LoginHistory, MobilisPhonePrefixes,
    OtpLogs, RefreshTokens, UserSessions
)
from .serializers import (
    UsersSerializer, AuditLogsSerializer, LoginHistorySerializer,
    MobilisPhonePrefixesSerializer, OtpLogsSerializer,
    RefreshTokensSerializer, UserSessionsSerializer
)
from .authentication import LegacyTokenAuthentication
from .permissions import IsAdminUser

# -----------------------------
# Auth Views (Public)
# -----------------------------

class RequestOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        if not phone_number:
            return Response({"error": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Logic to generate and send OTP would go here.
        # For now, we'll mock it and log it to OtpLogs if needed, or just return success.
        # We should check if user exists?
        # User said "comersial(user) ... can only login".
        
        # Mock OTP generation
        otp = "12345" # Static for testing
        
        # Log to OtpLogs (optional, but good for "get otp" requirement if it means logging)
        # OtpLogs.objects.create(...) 
        
        return Response({"message": "OTP sent", "otp": otp}, status=status.HTTP_200_OK)

# ----------------------------------------------------------------------
# Verify OTP (simple mock – matches the client call)
# ----------------------------------------------------------------------
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        if not otp:
            return Response({"error": "OTP is required"},
                            status=status.HTTP_400_BAD_REQUEST)
        # Mock verification – the static OTP we generate above is "12345"
        if otp != "12345":
            return Response({"error": "Invalid OTP"},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)

# ----------------------------------------------------------------------
# Resend OTP (just re‑use the same mock logic)
# ----------------------------------------------------------------------
class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number') or request.data.get('phone')
        if not phone_number:
            return Response({"error": "Phone number is required"},
                            status=status.HTTP_400_BAD_REQUEST)
        # In a real system you would generate a new OTP; here we reuse the static one.
        return Response({"message": "OTP resent", "otp": "12345"},
                        status=status.HTTP_200_OK)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        
        if not phone_number or not otp:
            return Response({"error": "Phone number and OTP required"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP (Mock)
        if otp != "12345":
             return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Users.objects.get(phone_number=phone_number)
        except Users.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Create Session/Token
        token = str(uuid.uuid4())
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            access_token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(days=1),
            created_at=timezone.now(),
            is_active=True
        )

        return Response({"token": token, "role": user.role}, status=status.HTTP_200_OK)


# -----------------------------
# Base View for Admin Only
# -----------------------------
class AdminBaseView(APIView):
    authentication_classes = [LegacyTokenAuthentication]
    permission_classes = [IsAdminUser]

# -----------------------------
# Users: Full CRUD (Admin Only)
# -----------------------------
class UsersListCreateView(AdminBaseView):
    def get(self, request):
        users = Users.objects.all()
        serializer = UsersSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UsersSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersDetailView(AdminBaseView):
    def get_object(self, pk):
        try:
            return Users.objects.get(pk=pk)
        except Users.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = UsersSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = UsersSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def patch(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = UsersSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(status=status.HTTP_404_NOT_FOUND)
        user.delete()
        return Response(status=204)


# -----------------------------
# AuditLogs: Read-only (Admin Only)
# -----------------------------
class AuditLogsListView(AdminBaseView):
    def get(self, request):
        logs = AuditLogs.objects.all()
        serializer = AuditLogsSerializer(logs, many=True)
        return Response(serializer.data)


class AuditLogsDetailView(AdminBaseView):
    def get(self, request, pk):
        try:
            log = AuditLogs.objects.get(pk=pk)
        except AuditLogs.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = AuditLogsSerializer(log)
        return Response(serializer.data)


# -----------------------------
# LoginHistory: Read-only (Admin Only)
# -----------------------------
class LoginHistoryListView(AdminBaseView):
    def get(self, request):
        history = LoginHistory.objects.all()
        serializer = LoginHistorySerializer(history, many=True)
        return Response(serializer.data)


class LoginHistoryDetailView(AdminBaseView):
    def get(self, request, pk):
        try:
            history = LoginHistory.objects.get(pk=pk)
        except LoginHistory.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = LoginHistorySerializer(history)
        return Response(serializer.data)


# -----------------------------
# MobilisPhonePrefixes: Full CRUD (Admin Only)
# -----------------------------
class MobilisPhonePrefixesListCreateView(AdminBaseView):
    def get(self, request):
        prefixes = MobilisPhonePrefixes.objects.all()
        serializer = MobilisPhonePrefixesSerializer(prefixes, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MobilisPhonePrefixesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MobilisPhonePrefixesDetailView(AdminBaseView):
    def get_object(self, pk):
        try:
            return MobilisPhonePrefixes.objects.get(pk=pk)
        except MobilisPhonePrefixes.DoesNotExist:
            return None

    def get(self, request, pk):
        prefix = self.get_object(pk)
        if not prefix:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = MobilisPhonePrefixesSerializer(prefix)
        return Response(serializer.data)

    def put(self, request, pk):
        prefix = self.get_object(pk)
        if not prefix:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = MobilisPhonePrefixesSerializer(prefix, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def patch(self, request, pk):
        prefix = self.get_object(pk)
        if not prefix:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = MobilisPhonePrefixesSerializer(prefix, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        prefix = self.get_object(pk)
        if not prefix:
            return Response(status=status.HTTP_404_NOT_FOUND)
        prefix.delete()
        return Response(status=204)


# -----------------------------
# OtpLogs: GET + POST (Admin Only)
# -----------------------------
class OtpLogsListCreateView(AdminBaseView):
    def get(self, request):
        otps = OtpLogs.objects.all()
        serializer = OtpLogsSerializer(otps, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = OtpLogsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OtpLogsDetailView(AdminBaseView):
    def get_object(self, pk):
        try:
            return OtpLogs.objects.get(pk=pk)
        except OtpLogs.DoesNotExist:
            return None

    def get(self, request, pk):
        otp = self.get_object(pk)
        if not otp:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = OtpLogsSerializer(otp)
        return Response(serializer.data)

    def put(self, request, pk):
        otp = self.get_object(pk)
        if not otp:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = OtpLogsSerializer(otp, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def patch(self, request, pk):
        otp = self.get_object(pk)
        if not otp:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = OtpLogsSerializer(otp, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


# -----------------------------
# RefreshTokens: GET + optional PATCH/DELETE (Admin Only)
# -----------------------------
class RefreshTokensListView(AdminBaseView):
    def get(self, request):
        tokens = RefreshTokens.objects.all()
        serializer = RefreshTokensSerializer(tokens, many=True)
        return Response(serializer.data)


class RefreshTokensDetailView(AdminBaseView):
    def get_object(self, pk):
        try:
            return RefreshTokens.objects.get(pk=pk)
        except RefreshTokens.DoesNotExist:
            return None

    def get(self, request, pk):
        token = self.get_object(pk)
        if not token:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = RefreshTokensSerializer(token)
        return Response(serializer.data)

    def patch(self, request, pk):
        token = self.get_object(pk)
        if not token:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = RefreshTokensSerializer(token, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        token = self.get_object(pk)
        if not token:
            return Response(status=status.HTTP_404_NOT_FOUND)
        token.delete()
        return Response(status=204)


# -----------------------------
# UserSessions: GET + optional PATCH/DELETE (Admin Only)
# -----------------------------
class UserSessionsListView(AdminBaseView):
    def get(self, request):
        sessions = UserSessions.objects.all()
        serializer = UserSessionsSerializer(sessions, many=True)
        return Response(serializer.data)


class UserSessionsDetailView(AdminBaseView):
    def get_object(self, pk):
        try:
            return UserSessions.objects.get(pk=pk)
        except UserSessions.DoesNotExist:
            return None

    def get(self, request, pk):
        session = self.get_object(pk)
        if not session:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = UserSessionsSerializer(session)
        return Response(serializer.data)

    def patch(self, request, pk):
        session = self.get_object(pk)
        if not session:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = UserSessionsSerializer(session, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        session = self.get_object(pk)
        if not session:
            return Response(status=status.HTTP_404_NOT_FOUND)
        session.delete()
        return Response(status=204)
