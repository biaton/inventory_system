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