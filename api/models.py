# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class AuditLogs(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.ForeignKey('Users', models.DO_NOTHING, blank=True, null=True)
    action = models.CharField(max_length=100)
    resource = models.CharField(max_length=100, blank=True, null=True)
    details = models.JSONField(blank=True, null=True)
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'audit_logs'


class LoginHistory(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.ForeignKey('Users', models.DO_NOTHING)
    phone_number = models.CharField(max_length=10)
    otp_requested_at = models.DateTimeField(blank=True, null=True)
    otp_verified_at = models.DateTimeField(blank=True, null=True)
    login_status = models.CharField(max_length=50, blank=True, null=True)
    failure_reason = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'login_history'


class MobilisPhonePrefixes(models.Model):
    id = models.UUIDField(primary_key=True)
    prefix = models.CharField(unique=True, max_length=3)
    provider_name = models.CharField(max_length=50)
    is_active = models.BooleanField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'mobilis_phone_prefixes'


class OtpLogs(models.Model):
    id = models.UUIDField(primary_key=True)
    phone_number = models.CharField(max_length=10)
    otp_code = models.CharField(max_length=5)
    request_count = models.IntegerField(blank=True, null=True)
    max_requests = models.IntegerField(blank=True, null=True)
    first_requested_at = models.DateTimeField(blank=True, null=True)
    last_requested_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(blank=True, null=True)
    verification_attempts = models.IntegerField(blank=True, null=True)
    max_attempts = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'otp_logs'


class RefreshTokens(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.ForeignKey('Users', models.DO_NOTHING)
    token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(blank=True, null=True)
    revoked_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'refresh_tokens'


class UserSessions(models.Model):
    id = models.UUIDField(primary_key=True)
    user = models.ForeignKey('Users', models.DO_NOTHING)
    access_token_hash = models.CharField(max_length=255)
    device_id = models.CharField(max_length=255, blank=True, null=True)
    device_name = models.CharField(max_length=255, blank=True, null=True)
    platform = models.CharField(max_length=50, blank=True, null=True)
    app_version = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(blank=True, null=True)
    last_activity = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'user_sessions'


class Users(models.Model):
    id = models.UUIDField(primary_key=True)
    phone_number = models.CharField(unique=True, max_length=10)
    role = models.CharField(max_length=50)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    email = models.CharField(unique=True, max_length=100, blank=True, null=True)
    is_active = models.BooleanField(blank=True, null=True)
    failed_login_attempts = models.IntegerField(blank=True, null=True)
    locked_until = models.DateTimeField(blank=True, null=True)
    last_login = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'users'
