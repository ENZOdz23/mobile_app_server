from django.urls import path
from .views import (
    RequestOTPView, VerifyOTPView, ResendOTPView, LoginView,
    UsersListCreateView, UsersDetailView,
    AuditLogsListView, AuditLogsDetailView,
    LoginHistoryListView, LoginHistoryDetailView,
    MobilisPhonePrefixesListCreateView, MobilisPhonePrefixesDetailView,
    OtpLogsListCreateView, OtpLogsDetailView,
    RefreshTokensListView, RefreshTokensDetailView,
    UserSessionsListView, UserSessionsDetailView
)

urlpatterns = [
    # Auth
    path('auth/request-otp/', RequestOTPView.as_view(), name='request-otp'),
    path('auth/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('auth/resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('auth/login/', LoginView.as_view(), name='login'),

    # Users
    path('users/', UsersListCreateView.as_view(), name='users-list-create'),
    path('users/<uuid:pk>/', UsersDetailView.as_view(), name='users-detail'),

    # AuditLogs
    path('audit-logs/', AuditLogsListView.as_view(), name='audit-logs-list'),
    path('audit-logs/<uuid:pk>/', AuditLogsDetailView.as_view(), name='audit-logs-detail'),

    # LoginHistory
    path('login-history/', LoginHistoryListView.as_view(), name='login-history-list'),
    path('login-history/<uuid:pk>/', LoginHistoryDetailView.as_view(), name='login-history-detail'),

    # MobilisPhonePrefixes
    path('phone-prefixes/', MobilisPhonePrefixesListCreateView.as_view(), name='phone-prefixes-list-create'),
    path('phone-prefixes/<uuid:pk>/', MobilisPhonePrefixesDetailView.as_view(), name='phone-prefixes-detail'),

    # OtpLogs
    path('otp-logs/', OtpLogsListCreateView.as_view(), name='otp-logs-list-create'),
    path('otp-logs/<uuid:pk>/', OtpLogsDetailView.as_view(), name='otp-logs-detail'),

    # RefreshTokens
    path('refresh-tokens/', RefreshTokensListView.as_view(), name='refresh-tokens-list'),
    path('refresh-tokens/<uuid:pk>/', RefreshTokensDetailView.as_view(), name='refresh-tokens-detail'),

    # UserSessions
    path('user-sessions/', UserSessionsListView.as_view(), name='user-sessions-list'),
    path('user-sessions/<uuid:pk>/', UserSessionsDetailView.as_view(), name='user-sessions-detail'),
]
