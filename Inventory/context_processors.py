# Inventory/context_processors.py

from .models import SystemNotification

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