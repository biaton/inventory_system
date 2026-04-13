from .models import SystemNotification, UserAccess
from django.core.exceptions import PermissionDenied
from .decorators import require_module_access


def notification_processor(request):
    # I-check muna kung naka-login ang user bago hanapan ng notifications
    if request.user.is_authenticated:
        unread_notifs = SystemNotification.objects.filter(user=request.user, is_read=False)
        return {
            'unread_notif_count': unread_notifs.count(),
            'latest_notifs': unread_notifs[:5]  # Top 5 lang ipapakita sa bell dropdown natin
        }
    
    # Kung walang naka-login, ibalik ay zero
    return {
        'unread_notif_count': 0,
        'latest_notifs': []
    }

def rbac_modules(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return {'is_super_admin': True, 'user_modules': ['ALL_ACCESS']}
        try:
            access = request.user.access_rights
            if access.is_super_admin:
                return {'is_super_admin': True, 'user_modules': ['ALL_ACCESS']}
            
            # Kunin ang mga module codes
            modules = list(access.allowed_modules.values_list('code', flat=True))
            return {'is_super_admin': False, 'user_modules': modules}
        except Exception:
            pass
            
    return {'is_super_admin': False, 'user_modules': []}