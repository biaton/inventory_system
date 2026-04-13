from django.core.exceptions import PermissionDenied
from functools import wraps
from .models import UserAccess
from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps # 🚀 DAGDAG ITO

def allowed_roles(allowed_roles=[]):
    def decorator(view_func):
        @wraps(view_func) # 🚀 DAGDAG ITO (Sobrang importante nito sa Django)
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
                # Kung hindi pasok, i-kick pabalik sa dashboard at bigyan ng error
                messages.error(request, "Access Denied: Wala kang permission para buksan ang pahinang ito.")
                return redirect('dashboard') # Siguraduhing may 'dashboard' ka sa urls.py mo
                
        return wrapper_func
    return decorator

def require_module_access(module_code):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                raise PermissionDenied("Access Denied: Please login first.")

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
                    raise PermissionDenied(f"Access Denied: You do not have permission for module ({module_code}).")
            
            except Exception:
                raise PermissionDenied("Access Denied: No access rights configured for your account.")
        
        return _wrapped_view
    return decorator

def rbac_modules(request):
    """
    Automatic nitong iche-check ang access ng user kada bukas ng page 
    at ipapasa sa HTML bilang 'user_modules'.
    """
    if request.user.is_authenticated and request.user.email:
        try:
            access = UserAccess.objects.get(email__iexact=request.user.email)
            if access.is_super_admin:
                return {'is_super_admin': True, 'user_modules': ['ALL_ACCESS']}
            
            # Kunin ang mga module codes na may checkmark
            modules = list(access.allowed_modules.values_list('code', flat=True))
            return {'is_super_admin': False, 'user_modules': modules}
        except UserAccess.DoesNotExist:
            pass
            
    return {'is_super_admin': False, 'user_modules': []}