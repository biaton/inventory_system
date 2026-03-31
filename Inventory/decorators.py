from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib import messages

def allowed_roles(allowed_roles=[]):
    def decorator(view_func):
        def wrapper_func(request, *args, **kwargs):
            
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