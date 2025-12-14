from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Allows access only to Admin (Manager) users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.role == 'Manager')

class IsCommercialUser(permissions.BasePermission):
    """
    Allows access only to Commercial users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.role == 'Commercial')

class IsAdminOrCommercialReadOnly(permissions.BasePermission):
    """
    Admin has full access. Commercial has read-only access (GET, HEAD, OPTIONS).
    """
    def has_permission(self, request, view):
        if not request.user:
            return False
        if request.user.role == 'Manager':
            return True
        if request.user.role == 'Commercial':
            return request.method in permissions.SAFE_METHODS
        return False
