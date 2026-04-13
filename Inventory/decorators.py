from django.core.exceptions import PermissionDenied
from functools import wraps
from .models import UserAccess
from django.http import HttpResponse
from django.shortcuts import redirect, render # 🚀 BAGO: Nagdagdag tayo ng 'render' dito
from django.contrib import messages

def allowed_roles(allowed_roles=[]):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper_func(request, *args, **kwargs):
            
            # 🚀 SAFETY CHECK: Kung hindi siya naka-login, sipain papuntang login page!
            if not request.user.is_authenticated:
                messages.warning(request, "Please login to access this page.")
                return redirect('login') # Siguraduhing tama itong login URL name mo

            # 1. Kunin ang role ng naka-login na user
            group = None
            if hasattr(request.user, 'profile'):
                group = request.user.profile.role

            # 2. Check kung ang role niya ay nasa listahan ng pwede pumasok
            if group in allowed_roles or group == 'SYSTEM_ADMIN':
                # Kung pasok, ituloy ang pagbukas ng page
                return view_func(request, *args, **kwargs)
            else:
                # 🚀 BAGO: Imbes na redirect at message, ibabato natin ang Access Denied UI
                return render(request, 'Inventory/errors/access_denied.html', status=403)
                
        return wrapper_func
    return decorator

def require_module_access(module_code):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                # Pwede mo rin itong gawing redirect to login depende sa trip mo
                return render(request, 'Inventory/errors/access_denied.html', status=403)

            # Superusers (Django Admin) pass automatically
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            try:
                # Kunin ang access rights ng mismong user
                access = request.user.access_rights
                
                if access.is_super_admin:
                    return view_func(request, *args, **kwargs)
                
                if access.allowed_modules.filter(code=module_code).exists():
                    return view_func(request, *args, **kwargs)
                else:
                    # 🚀 BAGO: Ibabato ang UI kapag walang checkmark ang module
                    return render(request, 'Inventory/errors/access_denied.html', status=403)
            
            except Exception:
                # 🚀 BAGO: Ibabato ang UI kapag wala pang setup ang user account
                return render(request, 'Inventory/errors/access_denied.html', status=403)
        
        return _wrapped_view
    return decorator

def rbac_modules(request):
    """
    Automatic nitong iche-check ang access ng user kada bukas ng page 
    at ipapasa sa HTML bilang 'user_modules'.
    """
    if request.user.is_authenticated:
        try:
            # 🚀 UPDATE: Ginamit na natin ang per-user relationship (access_rights) 
            # imbes na mag-filter pa gamit ang email para mas accurate at walang bug.
            access = request.user.access_rights
            
            if access.is_super_admin:
                return {'is_super_admin': True, 'user_modules': ['ALL_ACCESS']}
            
            # Kunin ang mga module codes na may checkmark
            modules = list(access.allowed_modules.values_list('code', flat=True))
            return {'is_super_admin': False, 'user_modules': modules}
        
        except Exception:
            pass
            
    return {'is_super_admin': False, 'user_modules': []}