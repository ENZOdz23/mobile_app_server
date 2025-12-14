from rest_framework import serializers
from .models import (
    AuditLogs,
    LoginHistory,
    MobilisPhonePrefixes,
    OtpLogs,
    RefreshTokens,
    UserSessions,
    Users
)


# can be modifide to include or exclude specific fields

class AuditLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLogs
        fields = '__all__'  
        managed = False  # Django will not try to create/drop this table


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table


class MobilisPhonePrefixesSerializer(serializers.ModelSerializer):
    class Meta:
        model = MobilisPhonePrefixes
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table


class OtpLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OtpLogs
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table


class RefreshTokensSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefreshTokens
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table


class UserSessionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSessions
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table


class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'
        managed = False  # Django will not try to create/drop this table
