from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.template.loader import render_to_string
from django.core.management import call_command
from django.db.models.functions import Trim
from django.utils.html import strip_tags
from django.db.models.signals import pre_save
from django.core.paginator import Paginator
from django.db.models import Prefetch
from django.contrib import messages
from django.db import transaction
from django.utils import timezone
from django.db.models import Sum, Count, Q, F, When, DecimalField, Case, Value 
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.urls import reverse
from django.http import HttpResponseRedirect
from .decorators import allowed_roles
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings as django_settings
from django.contrib.auth.signals import user_login_failed
from django.core.exceptions import PermissionDenied
from .decorators import require_module_access
from functools import wraps
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from datetime import timedelta
from decimal import Decimal
from datetime import date
from datetime import datetime
import pandas as pd
import datetime
import secrets
import string
import random
import uuid
import json
import csv
import re
from .utils import ( 
    send_shipping_notification, 
    send_order_acknowledgement, 
    send_qc_rejection_alert, 
    log_system_action, 
    notify_admins, 
    send_in_app_notification, 
    send_new_material_request_alert, 
    send_assembly_completed_alert,
    send_stock_move_alert,
    send_stock_out_alert,
    send_po_approval_alert,
    send_po_approved_notification,
    alert_new_delivery_request,
    )
from .models import (
    Profile, 
    Item, 
    Location, 
    Supplier, 
    Contact, 
    CustomerOrder, 
    PurchaseOrder, 
    PurchaseOrderItem, 
    MaterialTag, 
    DeliveryRequest, 
    DeliveryRequestItem, 
    StockLog, 
    ShipmentSchedule, 
    SystemSetting,
    EmailRoute,
    SystemAuditLog,
    LocationMaster,
    SystemNotification,
    MachineAsset,
    MachineComponent,
    UserAccess,
    SystemModule,
    SystemModule, 
    UserAccess, 
    User,
)

@login_required
def user_access_view(request):
    # Auto-populate modules kung walang laman
    if not SystemModule.objects.exists():
        for code, name in SystemModule.MODULE_CHOICES:
            SystemModule.objects.get_or_create(code=code, defaults={'name': name})

    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        is_super_admin = request.POST.get('is_super_admin') == 'on'
        module_codes = request.POST.getlist('modules') 

        try:
            with transaction.atomic():
                target_user = User.objects.get(id=user_id)
                access, created = UserAccess.objects.get_or_create(user=target_user)
                
                access.is_super_admin = is_super_admin
                access.updated_by = request.user
                access.save()
                
                access.allowed_modules.clear()
                if not is_super_admin and module_codes:
                    modules = SystemModule.objects.filter(code__in=module_codes)
                    access.allowed_modules.add(*modules)
                    
                messages.success(request, f"Access rights updated for {target_user.username}.")
        except Exception as e:
            messages.error(request, f"Error saving access: {str(e)}")
        
        return redirect('user_access')

    # GET Request: Kunin lahat ng Registered Users
    search_query = request.GET.get('q', '').strip()
    users_list = User.objects.select_related('access_rights').all().order_by('-date_joined')
    
    if search_query:
        users_list = users_list.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        )

    modules = SystemModule.objects.filter(is_active=True).order_by('name')

    context = {
        'users_list': users_list,
        'modules': modules,
        'search_query': search_query
    }
    return render(request, 'Inventory/master/user_access.html', context)

    
# 1. ANG CUSTOM LOGIN VIEW
def custom_login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        # 🚀 FIX 1: Tinanggal natin ang spaces sa unahan at dulo just in case!
        email = request.POST.get('email', '').strip()
        p = request.POST.get('password', '').strip() 
        
        # 🚀 FIX 2: Gumamit ng __iexact para hindi maging case-sensitive (Juan@ vs juan@)
        user_obj = User.objects.filter(email__iexact=email).first()
        
        if user_obj:
            user = authenticate(request, username=user_obj.username, password=p)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    messages.error(request, "Your account has been suspended. Contact Admin.")
            else:
                messages.error(request, "Invalid email or password. Please make sure there are no spaces.")
        else:
            messages.error(request, "Email is not registered in the system.")

    return render(request, 'Inventory/login.html')

# 2. ANG CUSTOM LOGOUT VIEW
def custom_logout_view(request):
#   if request.user.is_authenticated:
#       log_system_action(request.user, 'SYSTEM', 'Authentication', f"User {request.user.username} logged out.", request)

    logout(request) # Ito ang magbubura ng session
    return redirect('login') # Babalik siya sa custom login page natin

@login_required
def view_profile(request):
    """ Pahina para makita ang detalye ng nakalog-in na user """
    return render(request, 'Inventory/profile/view_profile.html')

@login_required
def edit_profile(request):
    """ Pahina at logic para sa pag-update ng profile """
    if request.method == 'POST':
        user = request.user
        
        # Kukunin ang mga tinype sa HTML form at ise-save sa User model
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.email = request.POST.get('email', '').strip()
        user.save()
        
        # Tatawagin yung floating Toast Notification natin
        messages.success(request, "Account details updated successfully!")
        return redirect('view_profile')
        
    return render(request, 'Inventory/profile/edit_profile.html')

def change_password_view(request):
    if not request.user.is_authenticated:
        return redirect('login') 

    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # 1. I-check kung tama ang lumang password
        if not request.user.check_password(old_password):
            messages.error(request, "Error: Incorrect current password.")
            return redirect('change_password')
        
        # 2. I-check kung magkaparehas ang bago at confirm password
        if new_password != confirm_password:
            messages.error(request, "Error: New passwords do not match.")
            return redirect('change_password')
            
        # 🚀 3. BULLETPROOF BACKEND VALIDATION
        if len(new_password) < 8:
            messages.error(request, "Error: Password must be at least 8 characters.")
            return redirect('change_password')
        if not re.search(r'[A-Z]', new_password):
            messages.error(request, "Error: Password must contain at least one uppercase letter (A-Z).")
            return redirect('change_password')
        if not re.search(r'[a-z]', new_password):
            messages.error(request, "Error: Password must contain at least one lowercase letter (a-z).")
            return redirect('change_password')
        if not re.search(r'[0-9]', new_password):
            messages.error(request, "Error: Password must contain at least one number (0-9).")
            return redirect('change_password')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            messages.error(request, "Error: Password must contain at least one special character.")
            return redirect('change_password')

        # 4. I-save ang bagong password
        request.user.set_password(new_password)
        request.user.save()
        
        # Para hindi ma-log out ang user pagkatapos mag-change password
        update_session_auth_hash(request, request.user)
        
        messages.success(request, "Success! Your password has been updated securely.")
        return redirect('settings_master') 

    return render(request, 'Inventory/master/change_password.html')

@login_required
def dashboard_view(request):
    # ---------------------------------------------------------
    # 1. TOTAL INVENTORY VALUE & ACTIVE LOTS
    # ---------------------------------------------------------
    active_tags = MaterialTag.objects.filter(total_pcs__gt=0)
    total_active_lots = active_tags.count()

    item_prices = {
        item['item_code']: item['unit_price'] 
        for item in Item.objects.values('item_code', 'unit_price')
    }

    total_inventory_value = Decimal('0.00')
    
    # Ilo-loop natin lahat ng kahon/lots sa warehouse at i-mu-multiply sa presyo
    for tag in active_tags:
        # Hanapin ang presyo, kung walang naka-set sa Item Master, default ay 0.00
        price = item_prices.get(tag.item_code, Decimal('0.00'))
        total_inventory_value += Decimal(str(tag.total_pcs)) * price

    # ---------------------------------------------------------
    # 2. ALERTS: LOW STOCK & EXPIRING
    # ---------------------------------------------------------
    today = timezone.now().date()
    thirty_days = today + timedelta(days=30)
    alerts = []

    # --- A. LOW STOCK LOGIC (Global Total per Item) ---
    # I-group natin lahat ng active tags by item_code at i-sum ang total pcs
    item_stocks = MaterialTag.objects.values('item_code').annotate(
        total_stock=Sum('total_pcs')
    )
    
    # Kunin natin ang mga Min Stock na sinet sa Item Master
    master_items = {
        item['item_code']: item['min_stock'] 
        for item in Item.objects.values('item_code', 'min_stock')
    }

    # Fallback threshold kung hindi nila nalagyan sa Item Master
    sys_settings = SystemSetting.objects.first()
    default_threshold = sys_settings.low_stock_threshold if sys_settings else 50

    low_stock_count = 0
    low_stock_alerts_temp = []

    for stock in item_stocks:
        code = stock['item_code']
        total_qty = stock['total_stock'] or 0
        
        # Gamitin ang specific Min Stock ng item, kung 0, gamitin ang default
        item_threshold = master_items.get(code, 0)
        threshold_to_use = item_threshold if item_threshold > 0 else default_threshold

        # I-check kung mas mababa sa threshold ang GLOBAL TOTAL
        if total_qty <= threshold_to_use:
            low_stock_count += 1
            low_stock_alerts_temp.append({
                'item_code': code,
                'detail': f"Total: {total_qty} (Min: {threshold_to_use})",
                'type': 'Low Stock',
                'qty': total_qty # Gagamitin lang pang-sort
            })

    # Sort natin para yung pinaka-kaunti ang nasa taas, tapos kunin lang ang top 5
    low_stock_alerts_temp.sort(key=lambda x: x['qty'])
    alerts.extend(low_stock_alerts_temp[:5])


    # --- B. EXPIRING LOGIC (Per Lot/Tag) ---
    # Tama lang na per Tag ito dahil per kahon ang expiry date
    expiring_items = active_tags.filter(
        expiration_date__lte=thirty_days, 
        expiration_date__gte=today
    ).order_by('expiration_date')
    
    expiring_count = expiring_items.count()

    for item in expiring_items[:5]:
        days_left = (item.expiration_date - today).days if item.expiration_date else 0
        alerts.append({
            'item_code': item.item_code,
            'detail': f"Lot: {item.lot_no} | Exp: {days_left} days",
            'type': 'Expiring'
        })
    
    # --- C. TOTAL ALERT COUNT ---
    alert_count = low_stock_count + expiring_count

    # ---------------------------------------------------------
    # 3. PENDING TASKS / RELEASES (UPDATED PARA SA CUSTOMER ORDERS)
    # ---------------------------------------------------------
    try:
        # Kunin lahat ng pending na Customer Orders
        pending_items = CustomerOrder.objects.filter(order_status='Pending').order_by('order_date', 'id')
        
        # 🚀 BAGO: I-group natin sila gamit ang MAIN PO NO.
        main_po_dict = {}
        
        for item in pending_items:
            raw_order_no = item.order_no
            # Hiwain ang suffix para makuha ang Main PO
            if '-' in raw_order_no:
                main_po_no = "-".join(raw_order_no.split('-')[:-1])
            else:
                main_po_no = raw_order_no

            if main_po_no not in main_po_dict:
                main_po_dict[main_po_no] = {
                    'main_po_no': main_po_no,
                    'customers': set(), # Para makuha ang unique na pangalan ng clients
                    'sub_orders': set(), # Para mabilang kung ilang orders sa loob ng batch
                    'total_qty': 0.0
                }
            
            customer_name = item.customer.name if item.customer else 'Walk-in'
            main_po_dict[main_po_no]['customers'].add(customer_name)
            main_po_dict[main_po_no]['sub_orders'].add(item.order_no)
            main_po_dict[main_po_no]['total_qty'] += float(item.quantity or 0)

        # I-format para sa HTML
        unique_orders = []
        for main_po, data in main_po_dict.items():
            cust_list = list(data['customers'])
            
            # Kung higit sa isa ang customer, lagyan natin ng "and X others"
            if len(cust_list) > 1:
                display_customer = f"{cust_list[0]} and {len(cust_list) - 1} others"
            elif len(cust_list) == 1:
                display_customer = cust_list[0]
            else:
                display_customer = "Walk-in"

            unique_orders.append({
                'main_po_no': main_po,
                'customer_name': display_customer,
                'order_count': len(data['sub_orders']),
                'total_qty': data['total_qty']
            })

        pending_req_count = len(unique_orders)
        recent_pending_reqs = unique_orders[:5] # Top 5 Main POs lang ipapakita

    except Exception as e:
        print(f"DASHBOARD ERROR: {e}") 
        pending_req_count = 0
        recent_pending_reqs = []

    # ---------------------------------------------------------
    # NEW: INBOUND SHIPMENTS (Mga paparating na P.O.)
    # ---------------------------------------------------------
    try:
        # Kunin ang mga Approved/Pending na deliveries na paparating palang
        inbound_items = PurchaseOrder.objects.filter(
            ordering_status__in=['Approved', 'Pending Approval'],
            delivery_date__gte=today
        ).order_by('delivery_date')

        inbound_dict = {}
        for item in inbound_items:
            # I-group using Batch ID o Main PO
            bid = getattr(item, 'batch_id', item.po_no) or item.po_no
            if bid not in inbound_dict:
                supplier_name = item.supplier.name if hasattr(item, 'supplier') and item.supplier else 'Unknown Supplier'
                inbound_dict[bid] = {
                    'po_no': bid,
                    'supplier': supplier_name,
                    'delivery_date': item.delivery_date
                }
        
        unique_inbounds = list(inbound_dict.values())
        inbound_count = len(unique_inbounds)
        recent_inbound = unique_inbounds[:5] # I-limit sa top 5 sa dashboard

    except Exception as e:
        print(f"INBOUND ERROR: {e}")
        inbound_count = 0
        recent_inbound = []


    # Idagdag sa Context...
    context = {
        'total_inventory_value': total_inventory_value,
        'total_active_lots': total_active_lots,
        'alerts': alerts,
        'alert_count': alert_count,
        'recent_pending_reqs': recent_pending_reqs,
        'pending_req_count': pending_req_count,
        'inbound_count': inbound_count,
        'recent_inbound': recent_inbound,
    }

    
    return render(request, 'Inventory/dashboard.html', context)

def read_notification_view(request, notif_id):
    # Hanapin yung notification
    notif = get_object_or_404(SystemNotification, id=notif_id, user=request.user)
    
    # Mark as read
    notif.is_read = True
    notif.save()
    
    # Kung may link (e.g. papunta sa PO page), doon siya itatapon. Kung wala, sa dashboard.
    if notif.link:
        return redirect(notif.link)
    return redirect('dashboard')

# 1. ANG VIEW PARA SA TABLE (Master List)
@login_required(login_url='login')
@require_module_access('USER_MASTER')
def user_master_view(request):
    # Auto-create profile kung wala pa
    for old_user in User.objects.filter(profile__isnull=True):
        Profile.objects.create(user=old_user, role='ADMIN' if old_user.is_superuser else 'WH_STAFF')

    # ==========================================
    # 1. POST: ADD / EDIT / TOGGLE USER
    # ==========================================
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            username = request.POST.get('username').strip()
            email = request.POST.get('email').strip()
            is_active = True # 🚀 FIX: Automatic ACTIVE kapag bagong register!
            role = request.POST.get('role')
            company_name = request.POST.get('company_name').strip()
            contact_number = request.POST.get('contact_number').strip()

            if User.objects.filter(username=username).exists():
                messages.error(request, "Error: Username is already taken!")
            elif User.objects.filter(email__iexact=email).exists():
                messages.error(request, "Error: Email is already registered to another user!")
            else:
                try:
                    with transaction.atomic():
                        # Generate 10-character Random Temporary Password
                        alphabet = string.ascii_letters + string.digits
                        temp_password = ''.join(secrets.choice(alphabet) for i in range(10))

                        # 🚀 FIX 3: Gumamit ng create_user() para official password hashing
                        new_user = User.objects.create_user(
                            username=username, 
                            email=email, 
                            password=temp_password
                        )
                        new_user.is_active = is_active
                        new_user.save()

                        profile, created = Profile.objects.get_or_create(user=new_user)
                        profile.role = role
                        profile.company_name = company_name
                        profile.contact_number = contact_number
                        profile.save()

                        # HTML EMAIL SENDING
                        html_content = render_to_string('Inventory/emails/user_welcome_email.html', {
                            'username': username,
                            'email': email,
                            'password': temp_password,
                            'role': profile.get_role_display()
                        })
                        text_content = strip_tags(html_content) 

                        msg = EmailMultiAlternatives(
                            subject="Welcome to ASIA Integrated Machine Inc. WMS",
                            body=text_content,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            to=[email]
                        )
                        msg.attach_alternative(html_content, "text/html")
                        msg.send(fail_silently=False)

                    messages.success(request, f"Success! Account created and credentials emailed to {email}.")
                except Exception as e:
                    messages.error(request, f"System Error: {str(e)}")

        elif action == 'edit':
            user_id = request.POST.get('user_id')
            email = request.POST.get('email').strip()
            password = request.POST.get('password') # Pwedeng blanko
            
            try:
                target_user = User.objects.get(id=user_id)
                
                # Check kung yung email ay ginagamit na ng iba
                if User.objects.filter(email=email).exclude(id=user_id).exists():
                    messages.error(request, "Error: Email is already used by another account!")
                else:
                    with transaction.atomic():
                        target_user.email = email
                        target_user.is_active = request.POST.get('is_active') == 'True'
                        if password: # Kung nag-type ng bagong password
                            target_user.set_password(password)
                        target_user.save()

                        profile = target_user.profile
                        profile.role = request.POST.get('role')
                        profile.company_name = request.POST.get('company_name').strip()
                        profile.contact_number = request.POST.get('contact_number').strip()
                        profile.save()

                    messages.success(request, f"User profile for {target_user.username} updated successfully!")
            except Exception as e:
                messages.error(request, f"Error updating user: {str(e)}")

        elif action == 'toggle':
            user_id = request.POST.get('user_id')
            try:
                target_user = User.objects.get(id=user_id)
                # Bawal i-deactivate yung sarili mong account
                if target_user == request.user:
                    messages.error(request, "You cannot deactivate your own account.")
                else:
                    target_user.is_active = not target_user.is_active
                    target_user.save()
                    status = "activated" if target_user.is_active else "deactivated"
                    messages.success(request, f"Account for {target_user.username} has been {status}.")
            except Exception as e:
                messages.error(request, f"Error toggling status: {str(e)}")

        return redirect('user_master')

    # ==========================================
    # 2. GET: DISPLAY & SEARCH
    # ==========================================
    search_query = request.GET.get('q', '').strip()
    profiles = Profile.objects.select_related('user').all().order_by('-id')

    if search_query:
        profiles = profiles.filter(
            Q(user__username__icontains=search_query) | 
            Q(user__email__icontains=search_query) | 
            Q(company_name__icontains=search_query) | 
            Q(role__icontains=search_query)
        )

    return render(request, 'Inventory/master/user_master.html', { 
        'profiles': profiles,
        'search_query': search_query
    })

@login_required(login_url='login')
def register_user_view(request):
    if request.method == 'POST':
        # 1. Kunin lahat ng text mula sa HTML form
        username = request.POST.get('username').strip()
        password = request.POST.get('password')
        email = request.POST.get('email').strip()
        is_active = request.POST.get('is_active') == 'True'
        
        role = request.POST.get('role')
        company_name = request.POST.get('company_name').strip()
        contact_number = request.POST.get('contact_number').strip()

        # 2. Check kung may kapangalan na sa system
        if User.objects.filter(username=username).exists():
            messages.error(request, "Error: Username is already taken!")
            return redirect('register_user')

        try:
            with transaction.atomic():
                # Gawa muna ng base User
                new_user = User.objects.create(
                    username=username,
                    email=email,
                    is_active=is_active
                )
                new_user.set_password(password)
                new_user.save()

                # ANG BULLETPROOF FIX: Kunin kung meron na, gumawa kung wala pa
                profile, created = Profile.objects.get_or_create(user=new_user)
                
                # Tapos i-update natin ang mga details base sa form
                profile.role = role
                profile.company_name = company_name
                profile.contact_number = contact_number
                profile.save() # I-save sa database!

#                log_system_action(request.user, 'CREATE', 'User Master', f"Created new user account: {username} ({role})", request)

                try:
                    # Hanapin sa database kung sino ang dapat maka-alam nito
                    route = EmailRoute.objects.get(event_name='NEW_USER', is_active=True)
                    target_emails = route.get_email_list() # Kukunin yung email na tinype mo sa Admin
                    
                    if target_emails: # Kung may nakasulat na email
                        subject = f"ERP System Alert: New User Registered ({username})"
                        message = f"""
                        Hello,
                        
                        This is an automated system alert from ASIA Integrated machine Inc.
                        A new user account has been successfully created.
                        
                        Details:
                        - Username: {username}
                        - Role: {profile.get_role_display()}
                        - Company/Dept: {company_name}
                        
                        Please do not reply to this email.
                        """
                        # I-send ang email!
                        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, target_emails, fail_silently=False)
                
                except EmailRoute.DoesNotExist:
                    # Kung walang naka-setup sa Admin, wag mag-error. Ituloy lang ang proseso.
                    pass
            
            # 4. Success! Ibalik sa Listahan
            messages.success(request, f"Success! Account for {username} has been created.")
            return redirect('user_master') # Siguraduhing ito ang pangalan ng user list mo sa urls.py

        except Exception as e:
            messages.error(request, f"System Error: {str(e)}")
            return redirect('register_user')

    return render(request, 'Inventory/master/register_user.html')

@login_required
@require_module_access('SYS_CONFIG')
def item_master_view(request):
    # ==========================================
    # 1. POST: ADD / EDIT / DELETE / IMPORT
    # ==========================================
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            item_code = request.POST.get('item_code', '').strip().upper()
            description = request.POST.get('description', '').strip()
            category = request.POST.get('category', 'RAW').strip()
            uom = request.POST.get('uom', 'PCS').strip().upper()
            unit_price = request.POST.get('unit_price', 0.00)
            min_stock = int(request.POST.get('min_stock', 0) or 0)
            default_zone = request.POST.get('default_zone', '').strip().upper()
            initial_stock = int(request.POST.get('initial_stock', 0) or 0)

            if Item.objects.filter(item_code=item_code).exists():
                messages.error(request, f"Error: Item Code '{item_code}' already exists!")
            else:
                with transaction.atomic():
                    Item.objects.create(
                        item_code=item_code, description=description,
                        category=category, uom=uom, unit_price=unit_price,
                        min_stock=min_stock, default_zone=default_zone
                    )
                    
                    if initial_stock > 0:
                        loc_instance = LocationMaster.objects.filter(location_code=default_zone).first() if default_zone else None
                        tag = MaterialTag.objects.create(
                            item_code=item_code,
                            description=description,
                            lot_no=f"OB-{timezone.now().strftime('%y%m%d')}", 
                            total_pcs=initial_stock,
                            packing_type=uom,
                            arrival_date=timezone.now().date(),
                            inspection_status='Passed', 
                            location=loc_instance,
                            remarks="System Initial Opening Balance"
                        )
                        
                        StockLog.objects.create(
                            material_tag=tag,
                            action_type='REG',
                            old_qty=0,
                            new_qty=initial_stock,
                            change_qty=initial_stock,
                            user=request.user if request.user.is_authenticated else None,
                            notes="Initial System Data Entry"
                        )
                    
                # log_system_action(request.user, 'CREATE', 'Item Master', f"Registered item: {item_code}", request)
                messages.success(request, f"Success! Item '{item_code}' has been registered.")

        elif action == 'edit':
            item_id = request.POST.get('item_id')
            item_code = request.POST.get('item_code', '').strip().upper()
            try:
                item = Item.objects.get(id=item_id)
                if Item.objects.filter(item_code=item_code).exclude(id=item_id).exists():
                    messages.error(request, f"Error: Item Code '{item_code}' is already in use.")
                else:
                    item.item_code = item_code
                    item.description = request.POST.get('description', '').strip()
                    item.category = request.POST.get('category', 'RAW').strip()
                    item.uom = request.POST.get('uom', 'PCS').strip().upper()
                    item.unit_price = request.POST.get('unit_price', 0.00)
                    item.min_stock = int(request.POST.get('min_stock', 0) or 0)
                    item.default_zone = request.POST.get('default_zone', '').strip().upper()
                    item.save()
                    messages.success(request, f"Success! Item '{item_code}' updated.")
            except Exception as e:
                messages.error(request, f"Error updating item: {str(e)}")

        elif action == 'delete':
            item_id = request.POST.get('item_id')
            try:
                item = Item.objects.get(id=item_id)
                code = item.item_code
                item.delete()
                messages.success(request, f"Successfully removed {code} from the system.")
            except Exception as e:
                messages.error(request, f"Error deleting item: {str(e)}")
                
        # 🚀 BAGO: IMPORT EXCEL LOGIC
        elif action == 'import_excel':
            excel_file = request.FILES.get('excel_file')
            if not excel_file:
                messages.error(request, "No file uploaded.")
                return redirect('item_master')

            try:
                # Basahin ang excel kahit may konting dumi (Pandas handles this well)
                df = pd.read_excel(excel_file)
                
                # Strip spaces sa column headers para hindi mag-error kung may whitespace
                df.columns = df.columns.str.strip()
                
                # Required columns checking
                required_cols = ['Item Code', 'Description', 'Category', 'UOM', 'Unit Price', 'Min Stock', 'Zone']
                if not all(col in df.columns for col in required_cols):
                    messages.error(request, f"Invalid Excel Format! Please download and use the provided template.")
                    return redirect('item_master')

                success_count = 0
                updated_count = 0
                
                with transaction.atomic():
                    for index, row in df.iterrows():
                        # Skip blank Item Codes
                        if pd.isna(row['Item Code']):
                            continue
                            
                        i_code = str(row['Item Code']).strip().upper()
                        i_desc = str(row['Description']).strip() if pd.notna(row['Description']) else "NO DESCRIPTION"
                        i_cat = str(row['Category']).strip().upper() if pd.notna(row['Category']) else "RAW"
                        i_uom = str(row['UOM']).strip().upper() if pd.notna(row['UOM']) else "PCS"
                        
                        try:
                            i_price = float(row['Unit Price']) if pd.notna(row['Unit Price']) else 0.00
                        except ValueError:
                            i_price = 0.00
                            
                        try:
                            i_min = int(row['Min Stock']) if pd.notna(row['Min Stock']) else 0
                        except ValueError:
                            i_min = 0
                            
                        i_zone = str(row['Zone']).strip().upper() if pd.notna(row['Zone']) else ""

                        # Gamitin natin ang update_or_create para mag-overwrite kung may existing, at mag-create kung wala
                        obj, created = Item.objects.update_or_create(
                            item_code=i_code,
                            defaults={
                                'description': i_desc,
                                'category': i_cat,
                                'uom': i_uom,
                                'unit_price': i_price,
                                'min_stock': i_min,
                                'default_zone': i_zone
                            }
                        )
                        
                        if created:
                            success_count += 1
                        else:
                            updated_count += 1

                messages.success(request, f"Import Success! Registered {success_count} new items, Updated {updated_count} existing items.")
            except Exception as e:
                messages.error(request, f"Failed to import Excel file. Error: {str(e)}")

        return redirect('item_master')

    # ==========================================
    # 2. GET: LOAD PAGE AND SEARCH / EXPORT TEMPLATE
    # ==========================================
    
    # 🚀 BAGO: DOWNLOAD TEMPLATE LOGIC
    if request.GET.get('download_template') == 'true':
        df = pd.DataFrame(columns=['Item Code', 'Description', 'Category', 'UOM', 'Unit Price', 'Min Stock', 'Zone'])
        # Add sample row
        df.loc[0] = ['SAMPLE-001', 'Sample 10MM Bolt', 'RAW', 'PCS', 15.50, 100, 'RACK-A']
        
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="WMS_ItemMaster_Template.xlsx"'
        with pd.ExcelWriter(response, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Template')
        return response

    search_query = request.GET.get('q', '')
    items = Item.objects.all().order_by('-created_at')

    if search_query:
        items = items.filter(
            Q(item_code__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(category__icontains=search_query)
        )

    paginator = Paginator(items, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    for item in page_obj.object_list:
        stock_sum = MaterialTag.objects.filter(
            item_code=item.item_code, 
            total_pcs__gt=0
        ).aggregate(total=Sum('total_pcs'))['total'] or 0
        item.current_stock = stock_sum

    zones = LocationMaster.objects.values_list('zone', flat=True).distinct() if hasattr(LocationMaster, 'objects') else []
    zone_list = [z for z in zones if z] 

    context = {
        'items': page_obj,
        'search_query': search_query,
        'zones': zone_list,
        'categories': Item.CATEGORY_CHOICES,
        'uoms': Item.UOM_CHOICES,
    }
    return render(request, 'Inventory/master/item_master.html', context)

# 2. THE REGISTER NEW ITEM VIEW
def register_item_view(request):
    if request.method == 'POST':
        item_code = request.POST.get('item_code', '').strip().upper()
        description = request.POST.get('description', '').strip()
        category = request.POST.get('category', 'Raw Material').strip()
        uom = request.POST.get('uom', 'PCS').strip().upper()
        unit_price = request.POST.get('unit_price', 0.00)

        if Item.objects.filter(item_code=item_code).exists():
            messages.error(request, f"Error: Item Code '{item_code}' already exists!")
            return redirect('register_item')

        Item.objects.create(
            item_code=item_code,
            description=description,
            category=category,
            uom=uom,
            unit_price=unit_price
        )
        log_system_action(request.user, 'CREATE', 'Item Master', f"Registered new item: {item_code}", request)

        messages.success(request, f"Success! Item '{item_code}' has been registered.")
        return redirect('item_master')

    return render(request, 'Inventory/master/register_item.html')

# 3. THE EXPORT TO EXCEL VIEW
def export_items_view(request):
    # BINAGO: Pinalitan natin ng 'Item' model para tugma sa register_item_view mo
    items = Item.objects.all().values('item_code', 'description', 'category', 'uom', 'unit_price')
    
    # Gagamitin ang Pandas para gawing Excel
    df = pd.DataFrame(list(items))
    
    if not df.empty:
        # Rename headers para mas maganda sa Excel
        df.columns = ['Item Code', 'Description', 'Category', 'UOM', 'Unit Price'] 

    # Setup the HTTP Response para mag-download ng file
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="Item_Master_List.xlsx"'
    
    # I-save ang dataframe sa response
    df.to_excel(response, index=False)
    
    return response

def export_users_csv(request):
    # Setup the response headers para sa file download
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="System_User_Masterlist.csv"'

    writer = csv.writer(response)
    # Header Row
    writer.writerow(['Username', 'Email', 'Role', 'Company', 'Contact', 'Status', 'Last Login'])

    # Data Rows
    profiles = Profile.objects.select_related('user').all()
    for p in profiles:
        status = "Active" if p.user.is_active else "Suspended"
        last_login = p.user.last_login.strftime("%Y-%m-%d %H:%M") if p.user.last_login else "Never"
        
        writer.writerow([
            p.user.username,
            p.user.email,
            p.role,
            p.company_name if p.company_name else "N/A",
            p.contact_number if p.contact_number else "N/A",
            status,
            last_login
        ])

    return response

# 3. TOGGLE ACCOUNT STATUS logic (Fully Functional)
def toggle_user_status(request, user_id):
    if request.method == "POST":
        target_user = get_object_or_404(User, id=user_id)
        
        # Bawal i-deactivate ang sarili para hindi ma-lockout
        if target_user == request.user:
            messages.error(request, "Security Alert: You cannot deactivate your own administrative account.")
        else:
            target_user.is_active = not target_user.is_active
            target_user.save()
            
            status_msg = "activated" if target_user.is_active else "suspended"

            log_system_action(request.user, 'UPDATE', 'User Master', f"Account for {target_user.username} was {status_msg}.", request)

            messages.success(request, f"User {target_user.username} has been successfully {status_msg}.")
            
    return redirect('user_master')

# 4. EDIT USER (Placeholder for your form logic)
def edit_user(request, user_id):
    # Kukunin natin yung Profile gamit ang user_id
    profile = get_object_or_404(Profile, user_id=user_id)
    target_user = profile.user # Ito yung actual na User object

    if request.method == "POST":
        # 1. Update User Table Fields
        target_user.username = request.POST.get('username')
        target_user.email = request.POST.get('email')
        
        # String comparison kasi "True" o "False" ang galing sa HTML <select>
        is_active_val = request.POST.get('is_active') == 'True'
        
        # Bawal i-suspend ng Admin ang sarili niya (Security Guardrail)
        if target_user == request.user and not is_active_val:
            messages.error(request, "Security Alert: You cannot suspend your own administrative account.")
        else:
            target_user.is_active = is_active_val

        target_user.save()

        # 2. Update Profile Table Fields
        profile.role = request.POST.get('role')
        profile.company_name = request.POST.get('company_name')
        profile.contact_number = request.POST.get('contact_number')
        profile.save()

        log_system_action(request.user, 'UPDATE', 'User Master', f"Updated profile details for user: {target_user.username}", request)

        messages.success(request, f"Record for {target_user.username} has been successfully updated.")
        return redirect('user_master')
    
    # Kapag GET request (binuksan lang ang page), i-re-render natin yung form na may laman
    return render(request, 'Inventory/master/edit_user.html', {'profile': profile})

@login_required
@require_module_access('SYS_CONFIG')
def settings_master_view(request):
    # Ito ang magiging main hub menu
    return render(request, 'Inventory/master/settings_master.html')

def edit_item(request, pk):
    item = get_object_or_404(Item, pk=pk)
    if request.method == "POST":
        item.description = request.POST.get('description')
        item.uom = request.POST.get('uom')
        item.save()

        log_system_action(request.user, 'UPDATE', 'Item Master', f"Updated details for Item: {item.item_code}", request)
        
        messages.success(request, "Item record updated successfully.")
        return redirect('item_master')
    
    return render(request, 'Inventory/master/edit_item.html', {'item': item})

@login_required(login_url='login')
def delete_item(request, pk):
    # 1. Siguraduhing papasok lang 'to kapag pinindot na ang "Delete" button (POST)
    if request.method == "POST":
        item = get_object_or_404(Item, pk=pk)
        
        # 2. I-save muna natin ang Item Code bago natin burahin sa database
        item_code_deleted = item.item_code 
        
        # 3. Burahin na ang item
        item.delete()
        
        # 4. 🚀 AUDIT LOG: (Pansinin: Dapat nakapasok ito sa loob ng 'if POST' block)
        log_system_action(
            user=request.user, 
            action='DELETE', 
            module='Item Master', 
            description=f"Deleted item record: {item_code_deleted}", 
            request=request
        )
        
        messages.success(request, "Item record has been removed.")
        
    # 5. Redirect pabalik sa listahan (Ito lang ang nasa labas ng if block)
    return redirect('item_master')


# --- LOCATION MASTER VIEW ---


# --- SUPPLIER MASTER VIEW ---
@login_required
@require_module_access('SYS_CONFIG')
def supplier_master(request):
    # ==========================================
    # 1. POST: ADD / EDIT / DELETE SUPPLIER
    # ==========================================
    if request.method == "POST":
        action = request.POST.get('action')
        
        if action == 'add':
            vendor_code = request.POST.get('vendor_code', '').strip().upper()
            name = request.POST.get('name', '').strip().upper()
            
            if Supplier.objects.filter(vendor_code=vendor_code).exists():
                messages.error(request, f"Error: Vendor Code '{vendor_code}' already exists.")
            else:
                Supplier.objects.create(
                    vendor_code=vendor_code,
                    name=name,
                    contact_name=request.POST.get('contact_name', '').strip().upper(),
                    email=request.POST.get('email', '').strip(),
                    phone=request.POST.get('phone', '').strip(),
                    address=request.POST.get('address', '').strip().upper(),
                    avg_lead_time=int(request.POST.get('avg_lead_time', 7) or 7),
                    is_active=request.POST.get('is_active') == 'on'
                )
                log_system_action(request.user, 'CREATE', 'Supplier Master', f"Registered supplier: {name}", request)
                messages.success(request, f"Successfully registered supplier: {name}")

        elif action == 'edit':
            supp_id = request.POST.get('supplier_id')
            vendor_code = request.POST.get('vendor_code', '').strip().upper()
            
            try:
                supp = Supplier.objects.get(id=supp_id)
                # Siguraduhing walang kaparehas na vendor code maliban sa sarili niya
                if Supplier.objects.filter(vendor_code=vendor_code).exclude(id=supp_id).exists():
                    messages.error(request, f"Error: Vendor Code '{vendor_code}' is already in use.")
                else:
                    supp.vendor_code = vendor_code
                    supp.name = request.POST.get('name', '').strip().upper()
                    supp.contact_name = request.POST.get('contact_name', '').strip().upper()
                    supp.email = request.POST.get('email', '').strip()
                    supp.phone = request.POST.get('phone', '').strip()
                    supp.address = request.POST.get('address', '').strip().upper()
                    supp.avg_lead_time = int(request.POST.get('avg_lead_time', 7) or 7)
                    supp.is_active = request.POST.get('is_active') == 'on'
                    supp.save()
                    
                    log_system_action(request.user, 'UPDATE', 'Supplier Master', f"Updated supplier: {supp.name}", request)
                    messages.success(request, f"Supplier '{supp.name}' updated successfully!")
            except Exception as e:
                messages.error(request, f"Error updating supplier: {str(e)}")

        elif action == 'delete':
            supp_id = request.POST.get('supplier_id')
            try:
                supp = Supplier.objects.get(id=supp_id)
                name = supp.name
                # Sa WMS, mas maganda i-deactivate kaysa i-delete para hindi masira ang lumang PO records.
                # Pero dahil delete action ito, buburahin natin base sa structure mo:
                supp.delete() 
                messages.success(request, f"Successfully deleted supplier {name}.")
            except Exception as e:
                messages.error(request, f"Error deleting supplier: {str(e)}")

        return redirect('supplier_master')

    # ==========================================
    # 2. GET: DISPLAY AND SEARCH
    # ==========================================
    search_query = request.GET.get('q', '')
    suppliers = Supplier.objects.all().order_by('name')

    if search_query:
        suppliers = suppliers.filter(
            Q(name__icontains=search_query) | 
            Q(vendor_code__icontains=search_query)
        )

    paginator = Paginator(suppliers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'Inventory/master/supplier_master.html', {
        'suppliers': page_obj,
        'search_query': search_query
    })

def register_supplier(request):
    if request.method == "POST":
        name = request.POST.get('name')
        vendor_code = request.POST.get('vendor_code')
        contact_name = request.POST.get('contact_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        avg_lead_time = request.POST.get('avg_lead_time', 0)

        # Validation: Check kung may kaparehas na Vendor Code
        if Supplier.objects.filter(vendor_code=vendor_code).exists():
            messages.error(request, f"Error: Vendor Code '{vendor_code}' already exists.")
            return redirect('register_supplier')

        # I-save sa database
        new_supplier = Supplier.objects.create(
            name=name,
            vendor_code=vendor_code,
            contact_name=contact_name,
            email=email,
            phone=phone,
            avg_lead_time=avg_lead_time
        )

        # 🚀 I-RECORD SA SYSTEM AUDIT LOGS
        log_system_action(request.user, 'CREATE', 'Supplier Master', f"Registered new supplier: {name} ({vendor_code})", request)
        
        messages.success(request, f"Successfully registered supplier: {name}")
        return redirect('supplier_master')

    return render(request, 'Inventory/master/register_supplier.html')


def edit_supplier(request, pk):
    supplier = get_object_or_404(Supplier, pk=pk)
    
    if request.method == "POST":
        supplier.name = request.POST.get('name')
        supplier.vendor_code = request.POST.get('vendor_code')
        supplier.contact_name = request.POST.get('contact_name')
        supplier.email = request.POST.get('email')
        supplier.phone = request.POST.get('phone')
        supplier.avg_lead_time = request.POST.get('avg_lead_time', supplier.avg_lead_time)
        supplier.save()

        # 🚀 I-RECORD SA SYSTEM AUDIT LOGS
        log_system_action(request.user, 'UPDATE', 'Supplier Master', f"Updated details for supplier: {supplier.name}", request)

        messages.success(request, f"Supplier '{supplier.name}' updated successfully!")
        return redirect('supplier_master')
    
    return render(request, 'Inventory/master/edit_supplier.html', {'supplier': supplier})

@login_required(login_url='login')
def register_customer_view(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        contact_person = request.POST.get('contact_person', '').strip()
        phone = request.POST.get('phone', '').strip()
        email = request.POST.get('email', '').strip()
        address = request.POST.get('address', '').strip()

        # Validation: Iwas duplicate customer
        if Contact.objects.filter(name__iexact=name, contact_type='Customer').exists():
            messages.error(request, f"Error: Customer '{name}' already exists.")
            return redirect('register_customer')

        # I-save sa database as Customer
        Contact.objects.create(
            name=name,
            contact_type='Customer', # 🚀 Naka-hardcode na as Customer
            contact_person=contact_person,
            phone=phone,
            email=email,
            address=address
        )

        # 🚀 SYSTEM AUDIT LOG
        log_system_action(request.user, 'CREATE', 'Customer Master', f"Registered new customer: {name}", request)
        
        messages.success(request, f"Successfully registered customer: {name}")
        
        # Redirect sa listahan ng customers (gawa ka lang ng url na 'customer_master' kung wala pa)
        return redirect('customer_master') 

    return render(request, 'Inventory/master/register_customer.html')

@login_required
@require_module_access('SYS_CONFIG')
@login_required(login_url='login')
def customer_master_view(request):
    # ==========================================
    # 1. POST: ADD / EDIT / DELETE CUSTOMER
    # ==========================================
    if request.method == "POST":
        action = request.POST.get('action')

        if action == 'add':
            name = request.POST.get('name', '').strip().upper()
            if Contact.objects.filter(name=name, contact_type='Customer').exists():
                messages.error(request, f"Error: Customer '{name}' already exists.")
            else:
                Contact.objects.create(
                    name=name,
                    contact_type='Customer',
                    contact_code=request.POST.get('contact_code', '').strip().upper(),
                    contact_person=request.POST.get('contact_person', '').strip().upper(),
                    email=request.POST.get('email', '').strip(),
                    phone=request.POST.get('phone', '').strip(),
                    address=request.POST.get('address', '').strip().upper(),
                    route_code=request.POST.get('route_code', '').strip().upper(),
                    preferred_transport=request.POST.get('preferred_transport', '').strip().upper(),
                    is_active=request.POST.get('is_active') == 'on'
                )
                # log_system_action(request.user, 'CREATE', 'Customer Master', f"Added client: {name}", request)
                messages.success(request, f"Successfully registered customer: {name}")

        elif action == 'edit':
            cust_id = request.POST.get('customer_id')
            name = request.POST.get('name', '').strip().upper()
            try:
                cust = Contact.objects.get(id=cust_id)
                # Ensure no name collision with other records
                if Contact.objects.filter(name=name, contact_type='Customer').exclude(id=cust_id).exists():
                    messages.error(request, f"Error: Customer Name '{name}' is already in use.")
                else:
                    cust.name = name
                    cust.contact_code = request.POST.get('contact_code', '').strip().upper()
                    cust.contact_person = request.POST.get('contact_person', '').strip().upper()
                    cust.email = request.POST.get('email', '').strip()
                    cust.phone = request.POST.get('phone', '').strip()
                    cust.address = request.POST.get('address', '').strip().upper()
                    cust.route_code = request.POST.get('route_code', '').strip().upper()
                    cust.preferred_transport = request.POST.get('preferred_transport', '').strip().upper()
                    cust.is_active = request.POST.get('is_active') == 'on'
                    cust.save()
                    
                    # log_system_action(request.user, 'UPDATE', 'Customer Master', f"Updated client: {name}", request)
                    messages.success(request, f"Customer '{name}' updated successfully!")
            except Exception as e:
                messages.error(request, f"Error updating customer: {str(e)}")

        elif action == 'delete':
            cust_id = request.POST.get('customer_id')
            try:
                cust = Contact.objects.get(id=cust_id)
                name = cust.name
                cust.delete()
                messages.success(request, f"Successfully deleted customer {name}.")
            except Exception as e:
                messages.error(request, f"Error deleting customer: {str(e)}")

        return redirect('customer_master')

    # ==========================================
    # 2. GET: DISPLAY & SEARCH
    # ==========================================
    search_query = request.GET.get('q', '').strip()
    customers = Contact.objects.filter(contact_type='Customer').order_by('name')

    if search_query:
        customers = customers.filter(
            Q(name__icontains=search_query) | 
            Q(contact_person__icontains=search_query) |
            Q(contact_code__icontains=search_query) |
            Q(email__icontains=search_query)
        )

    paginator = Paginator(customers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'Inventory/master/customer_master.html', {
        'customers': page_obj,
        'search_query': search_query
    })

# --- CUSTOMER ORDER VIEWS ---
@login_required
@require_module_access('CUSTOMER_ORDER')
def order_input_manual_view(request):
    if request.method == "POST":
        # 1. Kunin ang MAIN HEADER (Global info)
        main_po_no = request.POST.get('main_po_no', 'SO-GENERAL')
        main_status = request.POST.get('main_status', 'Pending')
        main_delivery_date = request.POST.get('main_delivery_date')
        main_transport = request.POST.get('main_transport', 'Truck')

        # 2. Kunin ang BATCH HEADERS (As lists)
        customers = request.POST.getlist('customer_name[]')
        contact_persons = request.POST.getlist('contact_person[]')
        delivery_addresses = request.POST.getlist('delivery_address[]') 
        del_dates = request.POST.getlist('delivery_date[]')
        order_types = request.POST.getlist('order_type[]')
        cust_po_nos = request.POST.getlist('cust_po_no[]')
        order_contents_list = request.POST.getlist('order_contents[]')
        remarks_list = request.POST.getlist('remarks[]')

        batch_orders = []

        try:
            # 🚀 Dahil inayos ng Magic Re-Indexer sa JS ang data, 
            # 100% safe na itong i-loop gamit ang range(len(customers))!
            for i in range(len(customers)):
                cust_name = customers[i].strip()
                if not cust_name: continue

                item_codes = request.POST.getlist(f'item_code_{i}[]')
                descriptions = request.POST.getlist(f'description_{i}[]') 
                qtys = request.POST.getlist(f'qty_{i}[]')
                units = request.POST.getlist(f'unit_{i}[]')
                prices = request.POST.getlist(f'price_{i}[]')

                order_items = []
                subtotal = 0.0 

                for j in range(len(item_codes)):
                    if item_codes[j].strip():
                        qty = float(qtys[j]) if j < len(qtys) and qtys[j] else 0.0
                        price = float(prices[j]) if j < len(prices) and prices[j] else 0.0
                        amount = qty * price
                        subtotal += amount 

                        order_items.append({
                            'item_code': item_codes[j].upper(),
                            'description': descriptions[j] if j < len(descriptions) else "", 
                            'qty': qty,
                            'unit': units[j] if j < len(units) else "PCS",
                            'price': price,
                            'amount': amount
                        })
                
                specific_del_date = del_dates[i] if i < len(del_dates) and del_dates[i] else main_delivery_date

                batch_orders.append({
                    'header': {
                        'order_no': f"{main_po_no}-{i+1}", 
                        'customer': cust_name,
                        'contact_person': contact_persons[i] if i < len(contact_persons) else "",
                        'delivery_address': delivery_addresses[i] if i < len(delivery_addresses) else "", 
                        'date': datetime.date.today().strftime('%Y-%m-%d'),
                        'delivery_date': specific_del_date,
                        'order_type': order_types[i] if i < len(order_types) else "Standard",
                        'cust_po_no': cust_po_nos[i] if i < len(cust_po_nos) else "",
                        'order_contents': order_contents_list[i] if i < len(order_contents_list) else "",
                        'status': main_status,
                        'transport': main_transport,
                        'remarks': remarks_list[i] if i < len(remarks_list) else "",
                        'grand_total': subtotal
                    },
                    'items': order_items
                })

        except Exception as e:
            print("Error parsing batch orders:", str(e))
            messages.error(request, "Format error detected. Please try again.")
            return redirect('order_manual')

        # 4. I-SAVE SA SESSION (Para sa Confirmation Page)
        request.session['batch_customer_orders'] = batch_orders
        return redirect('po_confirmation') 

    # ==========================================
    # GET REQUEST / LOADING THE PAGE
    # ==========================================
    customers = Contact.objects.filter(contact_type='Customer').order_by('name')
    items_list = Item.objects.all().order_by('item_code')
    delivery_addresses = Contact.objects.filter(contact_type='Customer').exclude(address__isnull=True).exclude(address__exact='').values_list('address', flat=True).distinct()

    return render(request, 'Inventory/customer_order/Order_Input_manual.html', {
        'customers': customers, 
        'items': items_list,
        'delivery_addresses': delivery_addresses 
    })

@login_required
@require_module_access('CUSTOMER_ORDER')
def order_input_excel_view(request):
    excel_data = []
    
    # 1. KUNG NAG-UPLOAD NG EXCEL FILE
    if request.method == "POST" and request.FILES.get('excel_file'):
        file = request.FILES['excel_file']
        try:
            if file.name.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file, engine='openpyxl')

            # Linisin ang column names
            df.columns = [c.replace(' ', '').strip() for c in df.columns]

            for _, row in df.iterrows():
                # Kuhain yung ItemCode sa Excel. Kung walang column na 'ItemCode', blank.
                # (Kung gusto mong hanapin yung salitang 'Product' o 'Code', dagdagan mo rito)
                item_code = str(row.get('ItemCode', row.get('Code', ''))).strip()
                if item_code and item_code != 'nan':
                    excel_data.append({
                        'item_code': item_code.upper(),
                        'qty': row.get('Quantity', row.get('Qty', 1)),
                        'price': row.get('Price', row.get('UnitPrice', 0.00)),
                        'description': str(row.get('Description', '')).strip()
                    })
        except Exception as e:
            messages.error(request, f"Error processing Excel file: {str(e)}")

    # 2. KUNG NAG-SUBMIT NA PARA I-SAVE ANG ORDER
    elif request.method == "POST" and request.POST.get('in_order_no'):
        # Kunin ang data sa header
        order_no = request.POST.get('in_order_no')
        cust_name = request.POST.get('customer_name')
        
        if not cust_name or not order_no:
            messages.error(request, "Order Number and Customer Name are required.")
            return redirect('order_excel')

        # Kunin ang arrays mula sa table
        item_codes = request.POST.getlist('item_code_row[]')
        cust_item_codes = request.POST.getlist('cust_item_code_row[]')
        descriptions = request.POST.getlist('description_row[]')
        del_dates = request.POST.getlist('del_date_row[]')
        transports = request.POST.getlist('transport_row[]')
        qtys = request.POST.getlist('qty_row[]')
        units = request.POST.getlist('unit_row[]')
        prices = request.POST.getlist('price_row[]')
        row_statuses = request.POST.getlist('status_row[]')

        order_items = []
        grand_total = 0.0

        for i in range(len(item_codes)):
            if item_codes[i].strip():
                qty = float(qtys[i]) if i < len(qtys) and qtys[i] else 0.0
                price = float(prices[i]) if i < len(prices) and prices[i] else 0.0
                amount = qty * price
                grand_total += amount

                order_items.append({
                    'item_code': item_codes[i].upper(),
                    'cust_item_code': cust_item_codes[i] if i < len(cust_item_codes) else "",
                    'description': descriptions[i] if i < len(descriptions) else "",
                    'del_date': del_dates[i] if i < len(del_dates) else "",
                    'transport': transports[i] if i < len(transports) else "Truck",
                    'qty': qty,
                    'unit': units[i] if i < len(units) else "PCS",
                    'price': price,
                    'amount': amount,
                    'status': row_statuses[i] if i < len(row_statuses) else "Pending"
                })

        formatted_order_no = f"{order_no}-1"
        
        pending_order = {
            'header': {
                'order_no': formatted_order_no, # Ito yung gagamitin sa database
                'customer': cust_name,
                'contact_person': request.POST.get('contact_person', ''),
                'delivery_address': request.POST.get('delivery_input', ''),
                'date': request.POST.get('order_date'),
                'order_type': request.POST.get('order_type', 'Standard'),
                'cust_po_no': request.POST.get('cust_po_no', ''),
                'order_contents': "EXCEL UPLOAD BATCH", # 🚀 BAGO: Kailangan ito para di mag-error
                'status': request.POST.get('order_status', 'Pending'),
                'transport': request.POST.get('transport_main', 'Truck'),
                'remarks': "Uploaded via Excel Module", # 🚀 BAGO: Default remark
                'grand_total': grand_total
            },
            'items': order_items
        }

        # Naka-batch structure (pero isa lang ang laman) para iisa lang ang Confirmation page
        request.session['batch_customer_orders'] = [pending_order]

        return redirect('po_confirmation')

    # 3. GET REQUEST (Page Load)
    customers = Contact.objects.filter(contact_type='Customer').order_by('name')
    items_list = Item.objects.all().order_by('item_code')
    delivery_addresses = Contact.objects.filter(contact_type='Customer').exclude(address__isnull=True).exclude(address__exact='').values_list('address', flat=True).distinct()

    return render(request, 'Inventory/customer_order/Order_Input_excel.html', {
        'excel_data': excel_data, 
        'customers': customers,
        'items': items_list, # 🚀 KINAKAILANGAN ITO PARA GUMANA YUNG LOCAL AUTO-FILL 
        'delivery_addresses': delivery_addresses
    })

@login_required
@require_module_access('CUSTOMER_ORDER')
def po_confirmation_view(request):
    # Kukunin natin yung 'batch_customer_orders' sa session
    batch_orders = request.session.get('batch_customer_orders')

    if not batch_orders:
        messages.error(request, "Session expired or no orders found. Please start again.")
        return redirect('order_manual')

    if request.method == "POST":
        try:
            with transaction.atomic():
                current_batch_id = f"BATCH-{uuid.uuid4().hex[:6].upper()}"
                total_orders_saved = 0
                
                # I-loop ang bawat Order sa Batch
                for order_data in batch_orders:
                    header = order_data.get('header')
                    items = order_data.get('items')
                    
                    if not items: continue # Wag i-save kung walang items
                    
                    # 1. Kunin o Gumawa ng Customer Profile
                    customer_obj, created = Contact.objects.get_or_create(
                        name=header.get('customer'),
                        defaults={
                            'contact_type': 'Customer',
                            'contact_person': header.get('contact_person', ''),
                            'address': header.get('delivery_address', '')
                        }
                    )

                    if not created:
                        if header.get('contact_person'): customer_obj.contact_person = header.get('contact_person')
                        if header.get('delivery_address'): customer_obj.address = header.get('delivery_address')
                        customer_obj.save()

                    # 2. Burahin ang luma kung ito ay correction
                    if header.get('is_correction'):
                        CustomerOrder.objects.filter(order_no=header.get('order_no')).delete()

                    # 3. I-save ang bawat item bilang CustomerOrder
                    grand_total = 0.0
                    for item in items:
                        amount = float(item.get('amount', 0.00))
                        grand_total += amount
                        
                        CustomerOrder.objects.create(
                            batch_id=current_batch_id,
                            order_no=header.get('order_no'),
                            customer=customer_obj,
                            order_date=header.get('date'),
                            order_type=header.get('order_type', 'Standard'), 
                            item_code=item.get('item_code'),
                            description=item.get('description', ''), 
                            quantity=item.get('qty', 0),
                            unit_price=item.get('price', 0.00),
                            amount=amount,
                            transport=header.get('transport', 'Motorcycle'),
                            order_status=header.get('status', 'Pending'),
                            remarks=header.get('remarks', ''),
                            contact_person=header.get('contact_person', ''),
                            delivery_address=header.get('delivery_address', '')
                        )
                        
                    total_orders_saved += 1
                    
                    # 4. System Logs & Email
                    action_type = 'UPDATE' if header.get('is_correction') else 'CREATE'
                    # log_system_action(...)
                    
                    customer_email = getattr(customer_obj, 'email', None) 
                    send_email_flag = request.POST.get('send_email') 
                    
                    if send_email_flag == 'on' and customer_email:
                        pass
                        # send_order_acknowledgement(...)

                # 5. Linisin ang session
                del request.session['batch_customer_orders']
                
                messages.success(request, f"Success! {total_orders_saved} Customer Order(s) posted to Database.")
                return redirect('order_manual') 
                
        except Exception as e:
            print(f"BOMBA SA DATABASE (CONFIRM ORDER): {e}")
            messages.error(request, f"Error saving order: {e}")
            return redirect('po_confirmation')

    # ==========================================
    # GET Request / Page Load
    # ==========================================
    
    # 🚀 BAGO: Kukunin natin ang Main PO No galing sa unang order
    main_po_no = "N/A"
    if batch_orders and len(batch_orders) > 0:
        first_order_no = batch_orders[0].get('header', {}).get('order_no', '')
        # Halimbawa: "MPO-260401-1234-1" -> "MPO-260401-1234"
        if '-' in first_order_no:
            main_po_no = "-".join(first_order_no.split('-')[:-1])

    return render(request, 'Inventory/customer_order/PO_Confirmation.html', {
        'batch_orders': batch_orders,
        'main_po_no': main_po_no, # 🚀 BAGO: Ipapasa sa HTML
    })

@login_required
@require_module_access('CUSTOMER_ORDER')
def order_correction_view(request):
    context = {}

    # ==========================================
    # 1. KUNG PININDOT ANG "SAVE CORRECTIONS" (POST)
    # ==========================================
    if request.method == "POST":
        batch_ref = request.POST.get('batch_ref')
        correction_reason = request.POST.get('correction_reason')
        
        item_ids = request.POST.getlist('item_id[]')
        qtys = request.POST.getlist('qty_row[]')
        unit_prices = request.POST.getlist('price_row[]')
        amounts = request.POST.getlist('amount_row[]')

        try:
            with transaction.atomic():
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_log = f"\n[CORRECTED on {current_time}] Reason: {correction_reason}"

                for i in range(len(item_ids)):
                    item = CustomerOrder.objects.get(id=item_ids[i])
                    item.quantity = qtys[i]
                    item.unit_price = unit_prices[i]
                    item.amount = amounts[i]
                    
                    item.order_status = 'Pending'
                    item.remarks = str(item.remarks or "") + audit_log
                    item.save() 

            messages.success(request, f"Success! Order Batch {batch_ref} has been corrected and sent back to Pending status.")
            return redirect('order_inquiry') # 🚀 BAGO: Ibabalik sa Inquiry imbes na Dashboard

        except Exception as e:
            messages.error(request, f"Error updating database: {str(e)}")
            return redirect(f'/customer-order/correction/?search_order={batch_ref}')

    # ==========================================
    # 2. KUNG NAG-SEARCH NG ORDER NUMBER (GET)
    # ==========================================
    search_query = request.GET.get('search_order', '').strip()
    
    if search_query:
        # 🚀 BAGO: Hahanapin niya kung eksakto, O KAYA kung nagsisimula sa Main PO, O KAYA kung Batch ID
        base_items = CustomerOrder.objects.filter(
            Q(order_no__startswith=search_query) | 
            Q(batch_id=search_query)
        )
        
        if base_items.exists():
            first_item = base_items.first()
            
            if hasattr(first_item, 'batch_id') and first_item.batch_id:
                batch_ref = first_item.batch_id
                all_items = CustomerOrder.objects.filter(batch_id=batch_ref).order_by('id')
            else:
                batch_ref = first_item.order_no
                all_items = base_items.order_by('id')

            # 🚀 BAGO: I-extract ang Main PO No para sa Display
            raw_order_no = first_item.order_no
            main_po_no = "-".join(raw_order_no.split('-')[:-1]) if '-' in raw_order_no else raw_order_no

            order_dict = {}
            for item in all_items:
                if item.order_no not in order_dict:
                    order_dict[item.order_no] = {
                        'header': {
                            'order_no': item.order_no,
                            'customer': item.customer.name if item.customer else '',
                            'cust_po_no': getattr(item, 'cust_po_no', ''),
                            'contact_person': getattr(item, 'contact_person', ''),
                            'delivery_address': getattr(item, 'delivery_address', ''),
                            'order_type': getattr(item, 'order_type', 'Standard'),
                            'remarks': getattr(item, 'remarks', ''),
                            'date': item.order_date.strftime('%Y-%m-%d') if item.order_date else '',
                            'transport': getattr(item, 'transport', ''),
                            'status': getattr(item, 'order_status', 'Pending'),
                        },
                        'items': []
                    }
                order_dict[item.order_no]['items'].append(item)

            context['grouped_orders'] = list(order_dict.values())
            context['batch_ref'] = batch_ref
            context['main_po_no'] = main_po_no # 🚀 BAGO: Pinasa natin sa UI
            context['searched'] = True
            
        else:
            messages.error(request, f"Order/Batch '{search_query}' not found.")
            context['searched'] = False

    context['search_query'] = search_query
    context['customers'] = Contact.objects.filter(contact_type='Customer').order_by('name')
    context['all_items'] = Item.objects.all().order_by('item_code')

    return render(request, 'Inventory/customer_order/Order_Correction.html', context)

@login_required
@require_module_access('CUSTOMER_ORDER')
def order_inquiry_view(request):
    search_query = request.GET.get('search', '').strip()
    
    qs = CustomerOrder.objects.all().order_by('-order_date', '-id')
    
    if search_query:
        qs = qs.filter(
            Q(order_no__icontains=search_query) |
            Q(customer__name__icontains=search_query) |
            Q(remarks__icontains=search_query)
        )

    # Dito na tayo mag-iipon base sa MAIN PO NO
    main_po_dict = {}
    overall_grand_total = 0.0
    
    for item in qs:
        # 🚀 BAGO: Hihiwain natin agad yung order_no para makuha ang Main PO
        raw_order_no = item.order_no
        if '-' in raw_order_no:
            main_po_no = "-".join(raw_order_no.split('-')[:-1])
        else:
            main_po_no = raw_order_no
            
        # Kung wala pa itong Main PO sa dictionary, gagawan natin
        if main_po_no not in main_po_dict:
            main_po_dict[main_po_no] = {}
        
        # Igrupo ang mga items sa ilalim ng specific na Customer Order (ex: SO-GENERAL-1)
        if item.order_no not in main_po_dict[main_po_no]:
            main_po_dict[main_po_no][item.order_no] = {
                'header': {
                    'order_no': item.order_no,
                    'cust_po_no': getattr(item, 'cust_po_no', 'N/A'), 
                    'customer': item.customer.name if item.customer else "Walk-in",
                    'order_date': item.order_date,
                    'transport': item.transport,
                    'status': item.order_status,
                    'delivery_address': getattr(item, 'delivery_address', ''),
                    'remarks': getattr(item, 'remarks', ''),
                    'grand_total': 0.0,
                },
                'items': []
            }
        
        # Idagdag ang item at i-compute ang total
        main_po_dict[main_po_no][item.order_no]['items'].append(item)
        
        amount = float(item.amount or 0)
        main_po_dict[main_po_no][item.order_no]['header']['grand_total'] += amount
        overall_grand_total += amount 

    # I-convert ang Dictionary papuntang List para sa HTML
    po_list = []
    for main_po, orders_in_po in main_po_dict.items():
        order_list = list(orders_in_po.values())
        main_order = order_list[0] 
        
        po_grand_total = sum(o['header']['grand_total'] for o in order_list)
        total_items_in_po = sum(len(o['items']) for o in order_list)
        
        # 🚀 FIX: Gagawa tayo ng safe alphanumeric ID para sa HTML Modal
        safe_html_id = "".join(e for e in main_po if e.isalnum())
        
        po_list.append({
            'main_po_no': main_po,
            'html_id': safe_html_id, # Gagamitin natin itong ID para sa pop-up modal
            'main_order': main_order,
            'all_orders': order_list, 
            'sub_orders_count': len(order_list), 
            'po_grand_total': po_grand_total,
            'total_items': total_items_in_po
        })

    # Bilangin ang mga summary sa taas
    total_orders_count = qs.values('order_no').distinct().count()
    total_pending = qs.filter(order_status='Pending').values('order_no').distinct().count()
    total_delivered = qs.filter(order_status='Delivered').values('order_no').distinct().count()

    paginator = Paginator(po_list, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'items': page_obj, 
        'search_query': search_query,
        'overall_grand_total': overall_grand_total,
        'total_orders_count': total_orders_count,
        'total_pending': total_pending,
        'total_delivered': total_delivered,
    }
    return render(request, 'Inventory/customer_order/Order_Inquiry.html', context)

@login_required
@require_module_access('CUSTOMER_ORDER')
def order_dispatch_view(request, batch_id):
    # 🚀 FIX: Yung 'batch_id' na pinapasa ng URL natin ngayon ay ang 'main_po_no' na talaga!
    main_po_no = batch_id 
    
    # 1. Kunin LAHAT ng items sa buong batch na Pending pa gamit ang order_no__startswith
    items = CustomerOrder.objects.filter(
        order_no__startswith=main_po_no, 
        order_status__in=['Pending', 'Processing']
    )
    
    if not items.exists():
        messages.error(request, "No pending orders found for this batch. It might already be dispatched.")
        return redirect('order_inquiry')

    if request.method == "POST":
        courier = request.POST.get('courier')
        tracking = request.POST.get('tracking')

        try:
            with transaction.atomic():
                # 2. Ipunin lahat ng unique na emails ng customers sa batch na ito
                orders_to_email = {}
                for item in items:
                    if item.customer and getattr(item.customer, 'email', None):
                        if item.order_no not in orders_to_email:
                            orders_to_email[item.order_no] = {
                                'email': item.customer.email,
                                'customer_name': item.customer.name
                            }

                # 3. I-UPDATE ANG STATUS NG BUONG BATCH SABAY-SABAY
                items.update(
                    order_status='Shipped',
                    transport=courier,
                    remarks=f"TRK: {tracking}"
                )

                # 4. SYSTEM LOG
                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Customer Order', 
                    description=f"Batch Dispatched {main_po_no} via {courier} (Tracking: {tracking})", 
                    request=request
                )

            # 5. 🚀 THE MAGIC: SEND EMAIL SA LAHAT NG CUSTOMER SA BATCH
            # Nilagay natin sa labas ng 'transaction.atomic' para kahit pumalya ang email ng isa, 
            # hindi mabu-bura yung database update mo!
            for order_no, data in orders_to_email.items():
                try:
                    send_shipping_notification(
                        order_no=order_no, 
                        customer_email=data['email'], 
                        courier_name=courier, 
                        tracking_number=tracking
                    )
                except Exception as email_err:
                    print(f"Failed to send shipping email to {data['email']}: {email_err}")

            messages.success(request, f"Success! Batch {main_po_no} dispatched successfully! Shipping emails sent to clients.")
            return redirect('order_inquiry') 

        except Exception as e:
            messages.error(request, f"System Error: {str(e)}")
            return redirect('order_dispatch', batch_id=batch_id)

    # 6. GROUP ITEMS BY CUSTOMER PARA SA UI
    grouped_orders = {}
    for item in items:
        if item.order_no not in grouped_orders:
            grouped_orders[item.order_no] = {
                'customer': item.customer.name if item.customer else "Unknown",
                'items': []
            }
        grouped_orders[item.order_no]['items'].append(item)

    context = {
        'batch_id': batch_id,
        'main_po_no': main_po_no,
        'grouped_orders': grouped_orders,
    }
    return render(request, 'Inventory/customer_order/order_dispatch.html', context)

@login_required
@require_module_access('CUSTOMER_ORDER')
def mark_delivered_view(request, order_no):
    # Hanapin ang order na 'Shipped' na
    items = CustomerOrder.objects.filter(order_no=order_no, order_status='Shipped')
    
    if items.exists():
        # Update natin ang status to Delivered
        items.update(order_status='Delivered')

        log_system_action(
            user=request.user, 
            action='UPDATE', 
            module='Customer Order', 
            description=f"Marked Order {order_no} as Delivered.", 
            request=request
        )

        messages.success(request, f"Success! Order #{order_no} is now marked as Delivered.")
    else:
        messages.error(request, f"Cannot update Order #{order_no}. It might not be shipped yet.")
        
    # I-redirect pabalik sa listahan ng orders (Inquiry view mo)
    # Palitan ang 'order_inquiry' ng tamang URL name ng listahan mo kung iba
    return redirect('order_inquiry')

# Purchase Order Views 
@login_required
@require_module_access('PURCHASE_ORDER')
def make_po_view(request):
    if request.method == "POST":
        # 1. Kunin ang MAIN HEADER (Global info)
        main_po_no = request.POST.get('main_po_no', 'PO-GENERAL')
        main_status = request.POST.get('main_status', 'Pending Approval')
        main_delivery_date = request.POST.get('main_delivery_date')
        main_transport = request.POST.get('main_transport', 'Truck')

        # 2. Kunin ang BATCH HEADERS (As lists)
        suppliers = request.POST.getlist('supplier[]')
        po_nos = request.POST.getlist('po_no[]')
        contact_persons = request.POST.getlist('contact_person[]')
        order_dates = request.POST.getlist('order_date[]')
        del_dates = request.POST.getlist('delivery_date[]')
        tax_terms = request.POST.getlist('tax_term[]')
        currencies = request.POST.getlist('currency[]')
        discount_rates = request.POST.getlist('discount_rate[]')
        remarks_list = request.POST.getlist('remarks[]')

        batch_pos = []

        try:
            # 3. I-loop ang bawat Supplier block
            for i in range(len(suppliers)):
                supp_name = suppliers[i].strip()
                if not supp_name: continue

                # Extract Items gamit ang specific block ID (`item_code_0[]`, `item_code_1[]`)
                item_codes = request.POST.getlist(f'item_code_{i}[]')
                descriptions = request.POST.getlist(f'description_{i}[]')
                packings = request.POST.getlist(f'packing_{i}[]')
                moqs = request.POST.getlist(f'moq_{i}[]')
                qtys = request.POST.getlist(f'qty_{i}[]')
                unit_prices = request.POST.getlist(f'unit_price_{i}[]')
                amortizations = request.POST.getlist(f'amortization_{i}[]')

                po_items = []
                subtotal = 0.0

                for j in range(len(item_codes)):
                    if item_codes[j].strip():
                        qty = float(qtys[j]) if j < len(qtys) and qtys[j] else 0.0
                        price = float(unit_prices[j]) if j < len(unit_prices) and unit_prices[j] else 0.0
                        amount = qty * price
                        subtotal += amount

                        is_amort = str(j + 1) in amortizations

                        po_items.append({
                            'item_code': item_codes[j].upper(),
                            'description': descriptions[j] if j < len(descriptions) else "",
                            'packing': float(packings[j]) if j < len(packings) and packings[j] else 1.0,
                            'moq': float(moqs[j]) if j < len(moqs) and moqs[j] else 1.0,
                            'qty': qty,
                            'unit_price': price,
                            'amount': amount,
                            'amortization': is_amort
                        })

                # Compute Tax per PO block
                tax_term = tax_terms[i] if i < len(tax_terms) else 'VAT Inclusive'
                disc_rate = float(discount_rates[i]) if i < len(discount_rates) and discount_rates[i] else 0.0
                
                discount_amount = subtotal * (disc_rate / 100)
                net_subtotal = subtotal - discount_amount
                tax_amount = net_subtotal * 0.12 if tax_term in ['VAT Inclusive', 'Taxable'] else 0.0
                grand_total = net_subtotal + tax_amount

                # Set fallback dates
                specific_order_date = order_dates[i] if i < len(order_dates) and order_dates[i] else datetime.date.today().strftime('%Y-%m-%d')
                specific_del_date = del_dates[i] if i < len(del_dates) and del_dates[i] else main_delivery_date

                batch_pos.append({
                    'header': {
                        'main_po_no': main_po_no, # Global reference
                        'po_no': po_nos[i] if i < len(po_nos) else f"{main_po_no}-{i+1}",
                        'supplier': supp_name,
                        'contact_person': contact_persons[i] if i < len(contact_persons) else "",
                        'order_date': specific_order_date,
                        'delivery_date': specific_del_date,
                        'transport': main_transport, # Galing sa global
                        'tax_term': tax_term,
                        'currency': currencies[i] if i < len(currencies) else 'PHP',
                        'discount_rate': disc_rate,
                        'status': main_status, # Galing sa global
                        'remarks': remarks_list[i] if i < len(remarks_list) else '',
                        'subtotal': subtotal,
                        'discount_amount': discount_amount,
                        'tax_amount': tax_amount,
                        'grand_total': grand_total
                    },
                    'items': po_items
                })

            # I-save sa Session at ipasa sa Confirm Page
            request.session['batch_pos'] = batch_pos
            return redirect('po_confirm_purchase') # Siguraduhing tugma sa URL name mo

        except Exception as e:
            messages.error(request, f"Error processing batch: {str(e)}")
            return redirect('make_po')

    # GET Request
    suppliers_list = Supplier.objects.filter(is_active=True).order_by('name')
    items_list = Item.objects.all().order_by('item_code')
    return render(request, 'Inventory/purchase_order/supplier_po.html', {
        'suppliers': suppliers_list,
        'items': items_list,
    })

@login_required
def api_search_item_master(request):
    """ Server-side search para sa Item Masterlist (Gagamitin sa PO Modals) """
    query = request.GET.get('q', '').strip()
    
    if not query:
        return JsonResponse({'success': False, 'error': 'Empty search query.'})

    try:
        # Hahanapin kung may match sa Item Code O KAYA sa Description
        from django.db.models import Q
        items = Item.objects.filter(
            Q(item_code__icontains=query) | Q(description__icontains=query)
        ).order_by('item_code')[:50] # Limit to 50 results para mabilis

        data = []
        for item in items:
            data.append({
                'item_code': item.item_code,
                'description': item.description or '',
                'category': item.get_category_display() if hasattr(item, 'get_category_display') else item.category,
                'uom': item.uom
            })

        return JsonResponse({'success': True, 'results': data})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_module_access('PURCHASE_ORDER')
def print_po_view(request):
    po_no = request.GET.get('po_no')
    
    if not po_no:
        messages.error(request, "Walang P.O. Number na ibinigay.")
        return redirect('make_po')
        
    # 1. Hanapin ang base PO
    base_po = PurchaseOrder.objects.filter(po_no=po_no).first()
    
    if not base_po:
        messages.error(request, "Hindi mahanap ang Purchase Order na ito.")
        return redirect('make_po')
        
    # 2. Hanapin ang buong batch kung meron
    if getattr(base_po, 'batch_id', None):
        po_qs = PurchaseOrder.objects.filter(batch_id=base_po.batch_id).prefetch_related('items').order_by('id')
    else:
        # Kung lumang P.O. na walang batch_id
        po_qs = [base_po]
        
    # 🚀 BAGO: ETO YUNG LOGIC PARA MA-EXTRACT ANG MAIN PO NO.
    first_po = po_qs[0] if po_qs else base_po
    raw_po_no = first_po.po_no
    main_po_no_str = "-".join(raw_po_no.split('-')[:-1]) if '-' in raw_po_no else raw_po_no

    pages_data = []
    
    # 3. I-loop at i-compute ang bawat P.O. sa loob ng batch
    for po in po_qs:
        po_items = po.items.all()
        
        # Computations per P.O.
        subtotal = sum((item.amount for item in po_items), Decimal('0.00'))
        discount_rate = Decimal(str(po.discount_rate or 0.0))
        discount_amount = subtotal * (discount_rate / Decimal('100'))
        net_subtotal = subtotal - discount_amount
        
        tax_amount = Decimal('0.00')
        if po.tax_term in ['VAT Inclusive', 'Taxable']:
            tax_amount = net_subtotal * Decimal('0.12')
            
        grand_total = net_subtotal + tax_amount
        
        # Idagdag sa listahan ng mga pahina na ipi-print
        pages_data.append({
            'po': po,
            'items': po_items,
            'subtotal': subtotal,
            'discount_amount': discount_amount,
            'tax_amount': tax_amount,
            'grand_total': grand_total,
        })
        
    context = {
        'pages_data': pages_data,
        'main_po': base_po, 
        'main_po_no': main_po_no_str, # 🚀 IPAPASA NA NATIN ANG MAIN PO NO
        'today': timezone.now()
    }
    return render(request, 'Inventory/purchase_order/print_po.html', context)

@login_required
def api_get_item_details(request):
    print("\n=== 🚀 PUMASOK SA api_get_item_details ===")
    print("RAW GET DATA:", request.GET)
    
    code = request.GET.get('code', '').strip()
    if not code:
        code = request.GET.get('item_code', '').strip()
        
    print(f"HINAHANAP NA CODE: '{code}'")

    if not code:
        print("❌ WALANG CODE NA NAPASA!")
        return JsonResponse({'success': False, 'error': 'No item code provided.'})

    try:
        item = Item.objects.filter(item_code__iexact=code).first()
        if item:
            stock_sum = MaterialTag.objects.filter(item_code__iexact=code, total_pcs__gt=0).aggregate(total=Sum('total_pcs'))['total'] or 0
            print(f"✅ NAHANAP SA DB! Desc: {item.description} | Stock: {stock_sum}")
            return JsonResponse({
                'success': True,
                'description': item.description or 'No Description',
                'uom': item.uom or 'PCS',
                'unit_price': float(item.unit_price or 0.0),
                'available_stock': stock_sum
            })
        else:
            print(f"❌ WALA SA DATABASE ANG '{code}'!")
            return JsonResponse({'success': False, 'error': f"Item '{code}' not found!"})
    except Exception as e:
        print(f"🔥 ERROR SA LOOB: {e}")
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_module_access('PURCHASE_ORDER')
def po_confirm_purchase_view(request):
    # ==========================================
    # 1. KUNG PININDOT ANG "SAVE TO DATABASE" (POST)
    # ==========================================
    if request.method == "POST":
        batch_pos = request.session.get('batch_pos')

        if not batch_pos:
            messages.error(request, "Session expired or no data found. Please try again.")
            return redirect('make_po')

        saved_pos_count = 0
        main_po_no_str = batch_pos[0].get('header', {}).get('main_po_no', 'PO-GENERAL') if batch_pos else 'UNKNOWN'

        try:
            with transaction.atomic():
                current_batch_id = main_po_no_str

                for po_data in batch_pos:
                    header = po_data.get('header')
                    items = po_data.get('items')

                    supplier_name = header.get('supplier')
                    supplier_obj = None
                    
                    if supplier_name:
                        # Subukang hanapin muna kung existing na ang supplier
                        supplier_qs = Supplier.objects.filter(name=supplier_name, is_active=True)
                        
                        if supplier_qs.exists():
                            supplier_obj = supplier_qs.first()
                        else:
                            # Kung wala talaga, tsaka lang gagawa ng bago
                            temp_vendor_code = f"VND-{uuid.uuid4().hex[:6].upper()}"
                            supplier_obj = Supplier.objects.create(
                                name=supplier_name,
                                vendor_code=temp_vendor_code,
                                contact_name=header.get('contact_person', '')
                            )
                    else:
                        raise ValueError("Supplier name is missing in one of the forms.")

                    # A. I-save ang Header sa PurchaseOrder Table
                    new_po = PurchaseOrder.objects.create(
                        batch_id=current_batch_id,
                        po_no=header.get('po_no'),
                        supplier=supplier_obj,
                        order_date=header.get('order_date') if header.get('order_date') else None,
                        transport=header.get('transport', 'Truck'),
                        tax_term=header.get('tax_term', 'VAT Inclusive'),
                        currency=header.get('currency', 'PHP'),
                        delivery_date=header.get('delivery_date') if header.get('delivery_date') else None,
                        discount_rate=header.get('discount_rate', 0.00),
                        remarks=header.get('remarks', ''),
                        ordering_status='Pending Approval', # Lahat ay mapupunta sa approval queue!
                        created_by=request.user,
                        po_amount_total=header.get('subtotal', 0.00), 
                        tax_amount_total=header.get('tax_amount', 0.00),
                        grand_total=header.get('grand_total', 0.00)
                    )

                    # B. BULK CREATE PARA SA ITEMS
                    po_items_to_save = []
                    for item in items:
                        po_item = PurchaseOrderItem(
                            purchase_order=new_po, 
                            item_code=item.get('item_code'),
                            description=item.get('description', ''),
                            packing=item.get('packing', 0),
                            moq=item.get('moq', 0),
                            qty=item.get('qty', 0),
                            unit_price=item.get('unit_price', 0.00),
                            amount=item.get('amount', 0.00),
                            is_amortized=item.get('amortization', False)
                        )
                        po_items_to_save.append(po_item)
                    
                    PurchaseOrderItem.objects.bulk_create(po_items_to_save)
                    saved_pos_count += 1

                # --- 🚀 MGA TINANGGAL NA LOGIC NOON NA IBINALIK NGAYON ---
                
                # 1. Log System Action
                log_system_action(
                    user=request.user, 
                    action='CREATE', 
                    module='Purchase Order', 
                    description=f"Created {saved_pos_count} new P.O.(s) under Batch ID {current_batch_id} (Main PO: {main_po_no_str}).", 
                    request=request
                )

                # 2. Lumipad ang Email Alert para sa PO Approval!
                try:
                    # Ipadala yung Batch ID at yung bilang ng POs sa email func
                    send_po_approval_alert(main_po_no_str, current_batch_id, saved_pos_count, request.user)
                except Exception as email_err:
                    print(f"PO Email Notification Error: {email_err}")

            # C. Linisin ang Session
            del request.session['batch_pos']

            messages.success(request, f"Success! {saved_pos_count} Purchase Order(s) saved and sent for approval.")
            return redirect('make_po') 

        except Exception as e:
            print("BOMBA SA DATABASE (CONFIRM PO):", str(e))
            messages.error(request, f"Error saving to database: {str(e)}")
            return redirect('po_confirm_purchase')

    # ==========================================
    # 2. KUNG PAG-LOAD LANG NG PAGE (GET)
    # ==========================================
    batch_pos = request.session.get('batch_pos')
    
    if not batch_pos:
        messages.warning(request, "No pending Purchase Order to confirm. Create one first.")
        return redirect('make_po')
        
    main_po_no = "N/A"
    overall_batch_total = 0.0

    if batch_pos and len(batch_pos) > 0:
        main_po_no = batch_pos[0].get('header', {}).get('main_po_no', 'N/A')

        for po in batch_pos:
            overall_batch_total += po.get('header', {}).get('grand_total', 0.00)

    context = {
        'batch_pos': batch_pos,
        'main_po_no': main_po_no,
        'overall_batch_total': overall_batch_total
    }
    
    return render(request, 'Inventory/purchase_order/PO_Confirmation.html', context)

@login_required
@require_module_access('PURCHASE_ORDER')    
def approve_po_view(request):
    if request.method == "POST":
        batch_id = request.POST.get('batch_id')
        action = request.POST.get('action') 

        if batch_id:
            pos_to_update = PurchaseOrder.objects.filter(batch_id=batch_id)
            new_status = 'Approved' if action == 'approve' else 'Cancelled'
            
            if pos_to_update.exists():
                po_count = pos_to_update.count()
                
                # 🚀 BAGO: Kunin kung sino ang gumawa (creator) ng unang PO sa batch
                first_po = pos_to_update.first()
                creator = first_po.created_by
                
                # I-update lahat ng P.O. sa ilalim ng batch na ito
                pos_to_update.update(ordering_status=new_status)
                
                if action == 'approve':
                    # 🚀 BAGO: Ipadala ang Email Notification
                    if creator and creator.email:
                        try:
                            send_po_approved_notification(
                                batch_id=batch_id,
                                po_count=po_count,
                                creator_email=creator.email,
                                creator_name=creator.username,
                                approver_name=request.user.username
                            )
                        except Exception as e:
                            print(f"PO Approval Email Error: {e}")
                    else:
                        print("User has no registered email. Skipped sending notification.")

                    messages.success(request, f"Success! Batch {batch_id} has been APPROVED.")
                else:
                    messages.error(request, f"Batch {batch_id} has been REJECTED.")
                
        return redirect('approve_po')

    # ==========================================
    # GET REQUEST / LOADING THE PAGE
    # ==========================================
    pending_qs = PurchaseOrder.objects.filter(
        ordering_status__in=['Pending Approval', 'Pending'] # Sinasalo pareho just in case
    ).prefetch_related('items').order_by('id')

    # I-group ang mga P.O. by Batch ID
    batches_dict = {}
    for po in pending_qs:
        bid = po.batch_id if po.batch_id else po.po_no # Fallback
        if bid not in batches_dict:
            batches_dict[bid] = []
        batches_dict[bid].append(po)

    grouped_batches = []
    for bid, pos in batches_dict.items():
        main_po = pos[0] # Ang pinakauna
        batch_grand_total = sum(p.grand_total for p in pos)
        
        # 🚀 BAGO: Extract Main PO No para malinis sa UI
        main_po_no = bid

        grouped_batches.append({
            'batch_id': bid,
            'main_po_no': main_po_no, # Ipasa natin ito sa HTML
            'main_po': main_po,
            'sub_pos': pos[1:], 
            'all_pos': pos,
            'total_pos': len(pos),
            'batch_grand_total': batch_grand_total
        })

    # KPI Cards Logic
    today = timezone.now().date()
    pending_count = len(grouped_batches)
    approved_today = PurchaseOrder.objects.filter(ordering_status='Approved', order_date=today).values('batch_id').distinct().count()
    rejected_count = PurchaseOrder.objects.filter(ordering_status='Cancelled').values('batch_id').distinct().count()

    context = {
        'grouped_batches': grouped_batches,
        'pending_count': pending_count,
        'approved_today': approved_today,
        'rejected_count': rejected_count,
    }
    
    return render(request, 'Inventory/purchase_order/PO_Approve.html', context)
    
@login_required
@require_module_access('PURCHASE_ORDER')
def po_inquiry_view(request):
    # 1. Kunin ang lahat ng PO at i-prefetch ang items
    po_qs = PurchaseOrder.objects.prefetch_related(
        Prefetch('items', queryset=PurchaseOrderItem.objects.all())
    ).order_by('-order_date', '-id')

    # 2. Kunin ang mga tinype ng user sa Search at Date fields
    search_query = request.GET.get('search', '').strip()
    from_date = request.GET.get('from_date', '')
    to_date = request.GET.get('to_date', '')

    # 3. I-apply ang Filters
    if search_query:
        po_qs = po_qs.filter(
            Q(po_no__icontains=search_query) | 
            Q(supplier__name__icontains=search_query) |
            Q(batch_id__icontains=search_query)
        )
    if from_date:
        po_qs = po_qs.filter(order_date__gte=from_date)
    if to_date:
        po_qs = po_qs.filter(order_date__lte=to_date)

    # 🚀 BAGO: Compute KPI Totals bago i-group by Batch
    overall_grand_total = po_qs.aggregate(total=Sum('grand_total'))['total'] or 0.00
    
    total_orders_count = po_qs.count()
    total_pending = po_qs.filter(ordering_status__in=['Pending Approval', 'Pending']).count()
    total_approved = po_qs.filter(ordering_status='Approved').count()

    # 4. I-group ang mga na-filter na POs by Batch ID
    batches_dict = {} 
    
    for po in po_qs:
        # Kunin ang batch_id, kung wala (legacy data), gamitin ang po_no
        bid = getattr(po, 'batch_id', po.po_no) or po.po_no
        if bid not in batches_dict:
            batches_dict[bid] = []
        batches_dict[bid].append(po)

    # 5. I-format ang grouped data para sa HTML
    grouped_batches = []
    for bid, pos in batches_dict.items():
        main_po = pos[0]
        batch_grand_total = sum(float(p.grand_total or 0) for p in pos)
        
        # 🚀 FIX: DITO TAYO NAGKAKAMALI DATI! 
        # Dahil ise-save na natin ang GPO-0000 as Batch ID, ang main_po_no ay EXACTLY yung bid!
        main_po_no = bid

        grouped_batches.append({
            'batch_id': bid,
            'main_po_no': main_po_no,
            'main_po': main_po,
            'sub_pos': pos[1:],
            'all_pos': pos,
            'total_pos': len(pos),
            'batch_grand_total': batch_grand_total
        })

    # 5. Pagination
    paginator = Paginator(grouped_batches, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'from_date': from_date,
        'to_date': to_date,
        'overall_grand_total': overall_grand_total,
        'total_orders_count': total_orders_count,
        'total_pending': total_pending,
        'total_approved': total_approved,
    }
    
    return render(request, 'Inventory/purchase_order/PO_Inquiry.html', context)

@login_required
@require_module_access('PURCHASE_ORDER')
def po_correction_view(request):
    context = {}

    # ==========================================
    # 1. POST: SAVE CORRECTIONS
    # ==========================================
    if request.method == "POST":
        batch_ref = request.POST.get('batch_ref')
        correction_reason = request.POST.get('correction_reason')
        
        item_ids = request.POST.getlist('item_id[]')
        qtys = request.POST.getlist('qty[]')
        unit_prices = request.POST.getlist('unit_price[]')
        amounts = request.POST.getlist('amount[]')

        try:
            with transaction.atomic():
                # A. Update Items
                for i in range(len(item_ids)):
                    item = PurchaseOrderItem.objects.get(id=item_ids[i])
                    item.qty = qtys[i]
                    item.unit_price = unit_prices[i]
                    item.amount = amounts[i]
                    item.save()

                # B. Hanapin ang POs sa Batch
                if batch_ref.startswith('BATCH-'):
                    pos_to_update = PurchaseOrder.objects.filter(batch_id=batch_ref)
                else:
                    pos_to_update = PurchaseOrder.objects.filter(po_no__startswith=batch_ref)
                
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_log = f"\n[CORRECTED on {current_time}] Reason: {correction_reason}"
                
                for po in pos_to_update:
                    po.remarks = str(po.remarks or "") + audit_log
                    po.ordering_status = 'Pending Approval'
                    
                    # C. Recompute Header Totals
                    new_subtotal = sum((i.amount for i in po.items.all()), Decimal('0.00'))
                    discount_val = new_subtotal * (Decimal(str(po.discount_rate or 0)) / Decimal('100'))
                    net_subtotal = new_subtotal - discount_val
                    
                    tax = Decimal('0.00')
                    if po.tax_term in ['VAT Inclusive', 'Taxable']:
                        tax = net_subtotal * Decimal('0.12')
                    
                    po.po_amount_total = new_subtotal
                    po.tax_amount_total = tax
                    po.grand_total = net_subtotal + tax
                    po.save()

            messages.success(request, f"Success! Batch {batch_ref} has been corrected and sent for approval.")
            return redirect('po_inquiry')

        except Exception as e:
            messages.error(request, f"Error updating database: {str(e)}")
            return redirect(f'/purchase-order/correction/?search_po={batch_ref}')

    # ==========================================
    # 2. GET: SEARCH PO/BATCH
    # ==========================================
    search_query = request.GET.get('search_po', '').strip()
    
    if search_query:
        # 🚀 BAGO: Search gamit ang startswith para makuha ang Main PO family
        base_qs = PurchaseOrder.objects.filter(
            Q(po_no__startswith=search_query) | Q(batch_id=search_query)
        )
        
        if base_qs.exists():
            first_po = base_qs.first()
            
            # Extract Main PO No para sa Header Display
            raw_po_no = first_po.po_no
            main_po_no = "-".join(raw_po_no.split('-')[:-1]) if '-' in raw_po_no else raw_po_no
            
            if first_po.batch_id:
                po_list = PurchaseOrder.objects.filter(batch_id=first_po.batch_id).prefetch_related('items').order_by('id')
                batch_ref = first_po.batch_id
            else:
                po_list = base_qs.prefetch_related('items').order_by('id')
                batch_ref = search_query

            context['po_list'] = po_list
            context['batch_ref'] = batch_ref
            context['main_po_no'] = main_po_no # 🚀 IPAPASA SA UI
            context['searched'] = True
        else:
            messages.error(request, f"P.O. '{search_query}' not found.")
            context['searched'] = False

    return render(request, 'Inventory/purchase_order/PO_Correction.html', context)

# Receiving / Inspection 
@login_required
@require_module_access('RECEIVING')
def ri_receive_view(request):
    context = {'searched': False}

    # ==========================================
    # 1. GET: PAG-SCAN NG PO BARCODE
    # ==========================================
    if request.method == "GET" and 'search_po' in request.GET:
        search_query = request.GET.get('search_po').strip()
        
        try:
            # 🚀 FIX: Tinanggal natin ang startswith. EXACT MATCH na lang sa batch_id o po_no!
            # Ibig sabihin, kapag nag-type ka ng GPO-0000, eksaktong buong batch ang kukunin niya.
            po_qs = PurchaseOrder.objects.filter(
                Q(batch_id__iexact=search_query) | 
                Q(po_no__iexact=search_query)
            ).prefetch_related('items')
            
            if po_qs.exists():
                valid_pos = []
                all_items = []
                already_received = True
                not_approved = True
                
                # I-filter ang mga valid na i-receive (Approved o Partial)
                for po in po_qs:
                    if po.ordering_status in ['Approved', 'Partial']:
                        valid_pos.append(po)
                        all_items.extend(list(po.items.all()))
                        already_received = False
                        not_approved = False
                    elif po.ordering_status == 'Received':
                        not_approved = False # Fully received na siya, hindi rejected
                
                if already_received and not not_approved:
                    messages.warning(request, f"Lahat ng items para sa '{search_query}' ay fully received na.")
                elif not_approved:
                    messages.warning(request, f"Ang '{search_query}' ay hindi pa Approved. Tanging Approved orders lang ang pwedeng i-receive.")
                else:
                    context['valid_pos'] = valid_pos
                    context['po_items'] = all_items
                    context['searched'] = True
                    context['search_ref'] = search_query
                    context['is_batch'] = len(valid_pos) > 1
            else:
                messages.error(request, f"Reference '{search_query}' not found in the database.")
                
        except Exception as e:
            messages.error(request, f"System Error: {str(e)}")

    # ==========================================
    # 2. POST: PAG-SAVE SA DATABASE (Receiving Confirmation Only)
    # ==========================================
    if request.method == "POST":
        search_ref = request.POST.get('search_ref')
        delivery_date = request.POST.get('delivery_date')

        try:
            with transaction.atomic():
                # 🚀 FIX: Exact match din dito sa POST para safe na safe ang data saving
                po_qs = PurchaseOrder.objects.filter(
                    Q(batch_id__iexact=search_ref) | Q(po_no__iexact=search_ref)
                )
                
                total_items_received_across_batch = 0

                # I-loop ang bawat Purchase Order na natagpuan
                for po_header in po_qs:
                    items_received_count = 0
                    all_items_fully_received = True

                    # I-loop ang items sa loob ng bawat PO
                    for item in po_header.items.all():
                        qty_received_str = request.POST.get(f'qty_received_{item.id}')
                        inspection_status = request.POST.get(f'inspection_{item.id}') # 🚀 BAGO: Kunin ang dropdown value
                        
                        if qty_received_str:
                            qty_received = int(qty_received_str)
                            if qty_received > 0:
                                
                                if hasattr(item, 'qty_received'):
                                    item.qty_received = (item.qty_received or 0) + qty_received
                                
                                # 🚀 BAGO: I-save ang Inspection Status papunta sa Database
                                if hasattr(item, 'status') and inspection_status:
                                    item.status = inspection_status

                                item.save()
                                
                                items_received_count += 1
                                total_items_received_across_batch += 1

                        # Check kung fully received na ba ang item na ito
                        if hasattr(item, 'qty_received') and hasattr(item, 'qty'):
                            if (item.qty_received or 0) < item.qty:
                                all_items_fully_received = False

                    # Kung may na-receive na kahit isang item sa PO na ito, update status
                    if items_received_count > 0:
                        po_header.ordering_status = 'Received' if all_items_fully_received else 'Partial'
                        if hasattr(po_header, 'actual_delivery_date') and delivery_date:
                            po_header.actual_delivery_date = delivery_date
                        po_header.save()

                if total_items_received_across_batch > 0:
                    # Optional: log_system_action(...)
                    
                    messages.success(request, f"Success! {total_items_received_across_batch} items from '{search_ref}' have been marked as received.")
                    # 🚀 Redirect sa material tagging gamit ang search_ref (GPO-0000)
                    return redirect(f"{reverse('material_tag')}?po_no={search_ref}") 
                else:
                    messages.warning(request, "No items were checked for receiving. Please ensure quantity is greater than zero.")

        except Exception as e:
            messages.error(request, f"Error processing receipt: {str(e)}")

    return render(request, 'Inventory/receiving/RI_receive.html', context)

@login_required
@require_module_access('RECEIVING')
def ri_delivery_request_view(request):
    if request.method == 'POST':
        try:
            # 1. Kunin ang Header Data mula sa Form
            delivery_place = request.POST.get('delivery_place')
            receiving_place = request.POST.get('receiving_place')
            reason = request.POST.get('reason')
            delivery_date = request.POST.get('delivery_date')
            remarks_header = request.POST.get('remarks') # Header remarks

            model_name = request.POST.get('model_name')
            production_no = request.POST.get('production_no')
            maker_name = request.POST.get('maker_name')
            part_name = request.POST.get('part_name')
            po_no = request.POST.get('po_no')

            # 2. Kunin ang Lists ng Items mula sa Dynamic Table
            # Gumagamit tayo ng getlist dahil marami itong entries
            item_codes = request.POST.getlist('item_code[]')
            descriptions = request.POST.getlist('description[]')
            revisions = request.POST.getlist('revision[]')
            request_qtys = request.POST.getlist('request_qty[]')
            item_remarks = request.POST.getlist('item_remarks[]')

            # Validation: Siguraduhin na may items
            if not item_codes:
                messages.error(request, "Please add at least one item to the request.")
                return redirect('delivery_request')

            # 3. Auto-Generate Request Number (REQ-YYYYMMDD-001)
            today_str = datetime.date.today().strftime('%Y%m%d')
            prefix = f"REQ-{today_str}-"
            last_req = DeliveryRequest.objects.filter(request_no__startswith=prefix).order_by('-request_no').first()
            
            if last_req:
                last_seq = int(last_req.request_no.split('-')[-1])
                new_seq = str(last_seq + 1).zfill(3)
            else:
                new_seq = "001"
            
            new_request_no = f"{prefix}{new_seq}"

            # 4. Save everything using a Database Transaction
            with transaction.atomic():
                new_request = DeliveryRequest.objects.create(
                    request_no=new_request_no,
                    delivery_place=delivery_place,
                    receiving_place=receiving_place,
                    reason=reason,
                    delivery_date=delivery_date,
                    remarks=remarks_header,
                    request_date=datetime.date.today(),
                    model_name=model_name,
                    production_no=production_no,
                    maker=maker_name,
                    part_name=part_name,
                    po_no=po_no
                )

                for i in range(len(item_codes)):
                    if not item_codes[i]:
                        continue
                        
                    DeliveryRequestItem.objects.create(
                        request_header=new_request,
                        item_code=item_codes[i],
                        description=descriptions[i],
                        revision=revisions[i],
                        request_qty=int(request_qtys[i]),
                        remarks=item_remarks[i]
                    )

            log_system_action(
                user=request.user, 
                action='CREATE', 
                module='Delivery Request', 
                description=f"Generated Delivery Request: {new_request_no} for {delivery_place}.", 
                request=request
            )

            # 🚀 FIX: Isang parameter na lang (new_request)
            try:
                alert_new_delivery_request(new_request)
            except Exception as email_e:
                print(f"Failed to send Delivery Request email: {email_e}")

            # 5. Success Message
            messages.success(request, f"Success! Movement Slip {new_request_no} has been registered.")
            return redirect('delivery_request')

        except Exception as e:
            # I-print sa terminal para sa debugging
            print(f"Error saving request: {str(e)}")
            messages.error(request, f"Failed to register request: {str(e)}")
            return redirect('delivery_request')

    # GET Request: I-render ang blank form
    context = {
        'now': datetime.datetime.now(),
        'title': 'Delivery Request',
        'locations': LocationMaster.objects.all().order_by('zone', 'location_code'), 
        'customers': Contact.objects.filter(contact_type='Customer').order_by('name'),
        'all_items': Item.objects.all().order_by('item_code') 
    }
    return render(request, 'Inventory/receiving/RI_delivery_request.html', context)

@login_required
def movement_slip_print_view(request, req_no):
    try:
        # 1. Kunin ang Main Header ng Request
        # Gagamit tayo ng get_object_or_404 para safe
        header = get_object_or_404(DeliveryRequest, request_no=req_no)

        # 2. Kunin lahat ng Items na nakadikit sa Request na ito
        # 'items' ang default related_name kung hindi mo binago sa models.py
        # Kung nag-error dito, i-check ang related_name sa ForeignKey ng items model mo
        items = header.items.all()

        # 3. I-prepare ang data na ipapasa sa HTML
        context = {
            'header': header,
            'items': items,
            'now': datetime.datetime.now(),  # Para sa 'Printed Date' sa slip
        }

        # 4. I-render ang printable template
        return render(request, 'Inventory/receiving/movement_slip_print.html', context)

    except Exception as e:
        # Kung may error (hal: hindi mahanap ang REQ), babalik sa main page
        messages.error(request, f"Error generating movement slip: {str(e)}")
        return redirect('delivery_request')

@login_required
def search_items(request):
    """
    Search view para sa Modal Stock Search.
    Nagpapadala ng listahan ng stocks sa frontend.
    """
    query = request.GET.get('q', '').strip()
    rev_query = request.GET.get('rev', '').strip()

    try:
        results = MaterialTag.objects.all()

        if query:
            results = results.filter(item_code__icontains=query)
        if rev_query:
            results = results.filter(revision__icontains=rev_query)

        results = results.order_by('-arrival_date')[:100]

        data = []
        for item in results:
            data.append({
                'item_code': item.item_code,
                'description': item.description or 'No description available',
                'stock_qty': item.total_pcs,  
                
                # 🚀 FIX: Tatanggalin na natin yung "Select Goods" na fallback, 
                # kapag walang revision sa database, ibabato niya ay empty string ('') na lang.
                'revision': item.revision if item.revision else ''
            })

        return JsonResponse({'success': True, 'results': data})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
        
# 2. Logic para sa Excel Import
@login_required
@require_module_access('RECEIVING')
def import_delivery_excel(request):
    # 1. Check kung POST at kung may file na 'excel_file' na dumating
    if request.method == 'POST' and request.FILES.get('excel_file'):
        # Gamitin natin ang pangalang 'excel_file' consistently
        excel_file = request.FILES['excel_file']
        
        try:
            # 2. Basahin ang excel_file gamit ang Pandas
            # Nilagyan natin ng engine='openpyxl' para sa .xlsx files
            df = pd.read_excel(excel_file, engine='openpyxl')
            
            # 3. Linisin ang headers (tanggalin ang spaces at gawing lowercase)
            df.columns = [str(c).strip().lower() for c in df.columns]
            
            # 4. I-convert ang data sa listahan ng dictionaries
            # Dapat ang columns sa Excel mo ay: item_code, description, stock_qty
            data = df.to_dict(orient='records')
            
            return JsonResponse({'success': True, 'items': data})
            
        except Exception as e:
            # I-print ang error sa terminal para sa debugging
            print(f"DEBUG ERROR: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'No file was uploaded.'})

@login_required
@require_module_access('RECEIVING')
def ri_material_tag_view(request):
    if request.method == 'POST':
        po_nos = request.POST.getlist('po_no[]')
        item_codes = request.POST.getlist('item_code[]')
        descriptions = request.POST.getlist('description[]')
        
        # 🚀 Kukunin ang Revision at Invoice mula sa Form
        revisions = request.POST.getlist('revision[]')
        invoices = request.POST.getlist('invoice[]') 
        
        lot_nos = request.POST.getlist('lot_no[]')
        total_pcs_list = request.POST.getlist('total_pcs[]')
        packing_units = request.POST.getlist('packing_unit[]') 
        container_counts = request.POST.getlist('container_count[]') 
        suppliers = request.POST.getlist('supplier[]')
        arrival_dates = request.POST.getlist('arrival_date[]')
        inspection_statuses = request.POST.getlist('inspection_status[]')
        
        new_tag_ids = []

        try:
            with transaction.atomic():
                for i in range(len(lot_nos)):
                    if not lot_nos[i]: continue 
                    
                    po_ref = PurchaseOrder.objects.filter(po_no=po_nos[i]).first()
                    containers = int(container_counts[i]) if i < len(container_counts) and container_counts[i] else 1
                    
                    # 🚀 FIX: Ise-save na natin yung Invoice at Revision sa Database!
                    # TANDAAN: Check kung 'invoice' o 'invoice_no' ang eksaktong pangalan sa models.py mo.
                    tag = MaterialTag.objects.create(
                        po_reference=po_ref,
                        item_code=item_codes[i],
                        description=descriptions[i], 
                        lot_no=lot_nos[i].upper(), 
                        
                        revision=revisions[i] if i < len(revisions) else '',
                        # ⚠️ Pinalitan ko ito pabalik sa 'invoice_no' (Base sa MaterialTag model mo)
                        invoice_no=invoices[i] if i < len(invoices) else '', 
                        
                        total_pcs=int(float(total_pcs_list[i])), 
                        packing_type=packing_units[i] if i < len(packing_units) else 'PCS',
                        container_count=containers, 
                        arrival_date=datetime.date.today(),
                        inspection_status=inspection_statuses[i] if i < len(inspection_statuses) else 'Pending'
                    )

                    StockLog.objects.create(
                        material_tag=tag,
                        action_type='REG',
                        old_qty=0,
                        new_qty=tag.total_pcs,
                        change_qty=tag.total_pcs,
                        user=request.user if request.user.is_authenticated else None,
                        notes=f"Initial Registration ({containers} Boxes) via {po_nos[i]}" 
                    )
                    new_tag_ids.append(str(tag.id))

            if new_tag_ids:
                ids_str = ",".join(new_tag_ids)
                log_system_action(
                    user=request.user, 
                    action='CREATE', 
                    module='Material Tagging', 
                    description=f"Manually registered {len(new_tag_ids)} Material Tags.", 
                    request=request
                )
                messages.success(request, f"Successfully registered {len(new_tag_ids)} tags!")
                
                print_url = f"{reverse('material_tag_print')}?ids={ids_str}"
                return HttpResponseRedirect(print_url)
            else:
                messages.error(request, "Walang nai-save! Siguraduhing may laman ang table.")
                return redirect('material_tag') 
                
        except Exception as e:
            import traceback
            error_msg = f"System Error: {str(e)} \nDetails: {traceback.format_exc()}"
            print(error_msg)
            messages.error(request, f"System Error: {str(e)}")
            return redirect('material_tag')

    # GET logic
    print_ids = request.session.pop('print_tag_ids', None)
    context = {
        'now': datetime.datetime.now(),
        'locations': LocationMaster.objects.all() if hasattr(LocationMaster, 'objects') else [],
        'print_ids': print_ids,
        'all_items': Item.objects.all(),
    }
    return render(request, 'Inventory/receiving/RI_material_tag.html', context)

@login_required
def get_item_details(request):
    print("\n=== 🚀 PUMASOK SA get_item_details ===")
    print("RAW GET DATA:", request.GET)
    
    # Sasaluhin natin pareho para walang lusot
    code = request.GET.get('code', '').strip()
    if not code:
        code = request.GET.get('item_code', '').strip()
        
    print(f"HINAHANAP NA CODE: '{code}'")

    if not code:
        print("❌ WALANG CODE NA NAPASA!")
        return JsonResponse({'success': False, 'error': 'No item code provided.'})

    try:
        item = Item.objects.filter(item_code__iexact=code).first()
        if item:
            stock_sum = MaterialTag.objects.filter(item_code__iexact=code, total_pcs__gt=0).aggregate(total=Sum('total_pcs'))['total'] or 0
            print(f"✅ NAHANAP SA DB! Desc: {item.description} | Stock: {stock_sum}")
            return JsonResponse({
                'success': True,
                'description': item.description or 'No Description',
                'uom': item.uom or 'PCS',
                'available_stock': stock_sum
            })
        else:
            print(f"❌ WALA SA DATABASE ANG '{code}'!")
            return JsonResponse({'success': False, 'error': f"Item '{code}' not found!"})
    except Exception as e:
        print(f"🔥 ERROR SA LOOB: {e}")
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def get_po_details(request):
    po_no = request.GET.get('po_no', '').strip()
    
    # Hanapin ang PO
    po = PurchaseOrder.objects.filter(po_no=po_no).first()
    
    if po:
        # Kunin ang unang item na nakakabit sa PO na ito
        # (Sa real-world, pwedeng loop ito kung marami, pero start muna tayo sa isa)
        item = po.items.first() 
        
        if item:
            return JsonResponse({
                'success': True,
                'po_no': po.po_no,
                'supplier': po.supplier.name if po.supplier else "N/A",
                'item_code': item.item_code,
                'description': item.description,
                'qty': item.qty,
                'revision': '00' # Default o kaya galing sa model mo
            })
            
    return JsonResponse({'success': False, 'error': 'Purchase Order not found or has no items.'})

@login_required
def get_po_for_tag(request):
    """ Hahanapin nito ang EXACT PO number na ita-type mo sa Material Tag page """
    po_no_query = request.GET.get('po_no', '').strip()
    
    if not po_no_query:
        return JsonResponse({'success': False, 'error': 'Please enter a PO Number.'})

    try:
        # 🚀 FIX: Tinanggal natin ang "startswith". EXACT MATCH na lang sa batch_id o po_no.
        po_qs = PurchaseOrder.objects.filter(
            Q(batch_id__iexact=po_no_query) | 
            Q(po_no__iexact=po_no_query)
        ).prefetch_related('items')
        
        if not po_qs.exists():
            return JsonResponse({'success': False, 'error': f'Purchase Order {po_no_query} not found!'})

        data_list = []
        
        for po_header in po_qs:
            # Kunin ang supplier name nang safe
            supplier_name = "Unknown Supplier"
            if hasattr(po_header, 'supplier') and po_header.supplier:
                supplier_name = str(po_header.supplier)
                
            for item in po_header.items.all():
                data_list.append({
                    'item_code': item.item_code,
                    'description': item.description if item.description else "No Description",
                    'po_no': po_header.po_no,
                    'supplier': supplier_name,
                    # Kung may qty_received, yun ang gamitin para sa tag. Kung wala, fallback sa ordered qty
                    'qty': getattr(item, 'qty_received', item.qty),  
                    'arrival_date': timezone.now().strftime('%Y-%m-%d'),
                    'revision': "-",
                    'invoice': "-",
                    'inspection_status': getattr(item, 'status', 'Pending')
                })
            
        return JsonResponse({'success': True, 'items': data_list})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def material_tag_print_view(request):
    ids_str = request.GET.get('ids', '')
    print_pages = [] # 🚀 Dito natin iipunin ang mga pages na ipi-print
    
    if ids_str:
        ids = ids_str.split(',')
        tags = MaterialTag.objects.filter(id__in=ids)
        
        for tag in tags:
            # Kunin kung ilan yung container, default ay 1
            containers = tag.container_count if hasattr(tag, 'container_count') and tag.container_count else 1
            
            # 🚀 VIRTUAL LOOP PARA SA PRINTING
            for c in range(containers):
                box_number = c + 1
                box_label = f"{box_number} OF {containers}" if containers > 1 else ""
                
                print_pages.append({
                    'tag': tag,
                    'box_label': box_label
                })
    
    return render(request, 'Inventory/receiving/material_tag_print.html', {'print_pages': print_pages})

@login_required
@require_module_access('RECEIVING')
def ri_storage_view(request):
    # 🚀 FIX: Gamitin natin ang LocationMaster imbes na yung lumang Location model
    if not LocationMaster.objects.exists():
        LocationMaster.objects.bulk_create([
            LocationMaster(location_code='RACK-A1', warehouse='MAIN WAREHOUSE', zone='ZONE A'),
            LocationMaster(location_code='RACK-A2', warehouse='MAIN WAREHOUSE', zone='ZONE A'),
            LocationMaster(location_code='RACK-B1', warehouse='MAIN WAREHOUSE', zone='ZONE B'),
            LocationMaster(location_code='PALLET-01', warehouse='TEMP STORAGE', zone='STAGING'),
        ])
        print("Sample locations created in LocationMaster!") 

    # Kunin lahat ng locations para sa dropdown at datalist
    locations = LocationMaster.objects.all().order_by('zone', 'location_code')
    
    return render(request, 'Inventory/receiving/RI_storage.html', {'locations': locations})

@login_required
def get_location_stock(request):
    """Kumukuha ng lahat ng items sa loob ng isang specific Location."""
    loc_id = request.GET.get('loc_id')
    if not loc_id:
        return JsonResponse({'success': False, 'error': 'No location provided.'})
    
    # Filter by location_id gamit ang MaterialTag
    tags = MaterialTag.objects.filter(location_id=loc_id, total_pcs__gt=0).order_by('-arrival_date')
    
    data = []
    for t in tags:
        data.append({
            'item_code': t.item_code,
            'description': t.description,
            'lot_no': t.lot_no,
            'qty': t.total_pcs,
            'arrival': t.arrival_date.strftime('%Y-%m-%d') if t.arrival_date else '---'
        })
    
    return JsonResponse({'success': True, 'stock': data})

@login_required
def process_storage_transfer(request):
    if request.method == 'POST':
        lot_no = request.POST.get('lot_no', '').strip().upper()
        loc_code = request.POST.get('location_code', '').strip().upper() 
        
        if not lot_no or not loc_code:
            return JsonResponse({'success': False, 'error': 'Missing Lot No or Location Code.'})

        try:
            # 🚀 FIX: .filter() ang gamitin
            tags = MaterialTag.objects.filter(lot_no=lot_no)
            if not tags.exists():
                return JsonResponse({'success': False, 'error': f'Material Tag {lot_no} not found!'})

            new_loc = LocationMaster.objects.get(location_code=loc_code)
            
            first_tag = tags.first()
            old_loc = first_tag.location
            old_loc_name = f"{old_loc.zone} | {old_loc.location_code}" if old_loc else "UNASSIGNED AREA"
            new_loc_name = f"{new_loc.zone} | {new_loc.location_code}"
            
            if old_loc == new_loc:
                return JsonResponse({'success': False, 'error': f'Batch is already stored in {loc_code}.'})

            # 🚀 FIX: I-loop lahat ng boxes sa Batch at i-update isa-isa
            boxes_count = tags.count()
            for tag in tags:
                tag.location = new_loc
                tag.save()
                
                StockLog.objects.create(
                    material_tag=tag,
                    action_type='MOVE',
                    old_qty=tag.total_pcs,
                    new_qty=tag.total_pcs,
                    change_qty=0,
                    notes=f"PUT-AWAY: Moved Batch (Box) from {old_loc_name} to {new_loc_name}",
                    user=request.user if request.user.is_authenticated else None
                )
            
            return JsonResponse({'success': True, 'message': f'Success! The entire batch {lot_no} ({boxes_count} boxes) is now stored in {loc_code}.'})
            
        except LocationMaster.DoesNotExist:
            return JsonResponse({'success': False, 'error': f'Location Barcode {loc_code} is invalid!'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'Invalid Request.'})

@login_required
def get_picking_list(request):
    """ Ito ang tinatawag ng Javascript kapag nag-scan ka ng Request No. """
    req_no = request.GET.get('req_no', '').strip()
    
    if not req_no:
        return JsonResponse({'success': False, 'error': 'No Request No. scanned.'})

    try:
        # Hanapin ang Request sa database (Palitan ng tamang Model name mo kung iba)
        inv_request = InventoryRequest.objects.get(request_no=req_no)
        
        # Kunin ang mga items sa loob ng request na 'yon
        items = inv_request.items.all()
        
        data_list = []
        for index, item in enumerate(items, start=1):
            data_list.append({
                'no': index,
                'item_id': item.id,
                'item_code': item.item_code,
                'description': item.description,
                'request_qty': item.request_qty,     
                'delivered_qty': item.delivered_qty,
                'remaining_qty': item.qty_requested - item.qty_delivered
            })
            
        return JsonResponse({'success': True, 'items': data_list})
        
    except DeliveryRequest.DoesNotExist: # 🚀 FIX: Tamang Exception
        return JsonResponse({'success': False, 'error': f'Request No {req_no} not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def api_get_material_tag(request):
    lot_no = request.GET.get('lot_no', '').strip().upper()
    
    if not lot_no:
        return JsonResponse({'success': False, 'error': 'No Lot Number provided.'})

    try:
        tags = MaterialTag.objects.filter(lot_no=lot_no)
        
        if not tags.exists():
            return JsonResponse({'success': False, 'error': f'Material Tag (Lot: {lot_no}) not found in database.'})

        first_tag = tags.first()
        po_no = first_tag.po_reference.po_no if first_tag.po_reference else "N/A"
        
        total_batch_qty = sum(t.total_pcs for t in tags)
        
        clean_desc = re.sub(r'\[Box \d+ of \d+\]', '', first_tag.description).strip()

        return JsonResponse({
            'success': True,
            'tag': {
                'item_code': first_tag.item_code,
                'description': clean_desc, 
                'po_no': po_no,
                'revision': first_tag.revision if first_tag.revision else '---',
                'arrival_date': first_tag.arrival_date.strftime('%Y-%m-%d') if first_tag.arrival_date else '-',
                'qty': total_batch_qty, 
                'current_loc': first_tag.location.location_code if first_tag.location else 'UNASSIGNED',
                # 🚀 FIX: Pinag-isa ko na lang ang invoice para hindi error
                'invoice': first_tag.invoice_no if first_tag.invoice_no else 'N/A', 
                'status': first_tag.inspection_status if hasattr(first_tag, 'inspection_status') else 'PENDING'
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def api_update_tag_status(request):
    if request.method == 'POST':
        lot_no = request.POST.get('lot_no', '').strip().upper()
        new_status = request.POST.get('status', '').strip().upper()
        
        try:
            # 🚀 FIX: .filter() at Loop
            tags = MaterialTag.objects.filter(lot_no=lot_no)
            if not tags.exists():
                return JsonResponse({'success': False, 'error': 'Lot Number not found.'})

            boxes_count = tags.count()
            for tag in tags:
                old_status = tag.inspection_status
                tag.inspection_status = new_status
                tag.save()
                
                StockLog.objects.create(
                    material_tag=tag,
                    action_type='QC',
                    old_qty=tag.total_pcs,
                    new_qty=tag.total_pcs,
                    change_qty=0,
                    notes=f"STATUS CHANGE: Batch updated from {old_status} to {new_status}",
                    user=request.user
                )
            
            return JsonResponse({'success': True, 'message': f'Batch {lot_no} ({boxes_count} boxes) is now {new_status}'})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'Invalid request method.'})


# ==========================================
# 2. MAIN VIEW: NAGLO-LOAD NG PAGE & NAGSE-SAVE
# ==========================================
@login_required
@require_module_access('RECEIVING')
def ri_picking_view(request):
    if request.method == "POST":
        req_no = request.POST.get('scan_request_no_hidden')
        
        if not req_no:
            messages.error(request, "No Request Number provided!")
            return redirect('ri_picking') # Palitan sa tamang URL name mo

        try:
            with transaction.atomic():
                # 🚀 BAGO: Ligtas na paghahanap ng Request
                # Dito mo pwedeng idagdag ang if-else kung may iba kang prefix para sa Inventory at WIP!
                try:
                    inv_request = DeliveryRequest.objects.get(request_no=req_no)
                except DeliveryRequest.DoesNotExist:
                    messages.error(request, f"Error: Request {req_no} not found in Delivery Requests.")
                    return redirect('ri_picking')
                
                # Defense: Baka tapos na 'tong request na 'to
                if inv_request.status == 'Completed':
                    messages.warning(request, f"Request {req_no} has already been completed.")
                    return redirect('ri_picking')

                all_items_completed = True
                total_picked_items = 0

                # 1. I-loop lahat ng items sa request table
                for req_item in inv_request.items.all():
                    pick_qty_str = request.POST.get(f'pick_qty_{req_item.id}')
                    pick_rev_str = request.POST.get(f'pick_rev_{req_item.id}')
                    pick_price_str = request.POST.get(f'pick_price_{req_item.id}')
                    
                    if pick_rev_str is not None:
                        req_item.revision = pick_rev_str.strip()

                    # 🚀 FIX: Ligtas na pag-convert sa float (Iwas ValueError kapag blanko)
                    if pick_price_str and pick_price_str.strip():
                        try:
                            req_item.unit_price = float(pick_price_str)
                        except ValueError:
                            req_item.unit_price = 0.00
                    
                    if pick_qty_str:
                        qty_to_pick = int(pick_qty_str)
                        
                        if qty_to_pick > 0:
                            # Defense: Baka sumobra yung pick sa remaining request
                            remaining_req = req_item.request_qty - req_item.delivered_qty
                            if qty_to_pick > remaining_req:
                                raise Exception(f"Cannot pick more than requested for {req_item.item_code}. Max allowed is {remaining_req}.")

                            # 🚀 2. FIFO INVENTORY DEDUCTION LOGIC
                            available_tags = MaterialTag.objects.filter(
                                item_code=req_item.item_code, 
                                total_pcs__gt=0
                            ).order_by('arrival_date', 'id')

                            qty_needed = qty_to_pick
                            
                            for tag in available_tags:
                                if qty_needed <= 0:
                                    break 
                                    
                                qty_to_take_from_tag = min(qty_needed, tag.total_pcs)
                                
                                # Ibawas sa Lot/Tag
                                tag.total_pcs -= qty_to_take_from_tag
                                tag.save()
                                
                                # I-record sa Stock Log kung saan nanggaling
                                StockLog.objects.create(
                                    material_tag=tag,
                                    action_type='OUT',
                                    old_qty=tag.total_pcs + qty_to_take_from_tag,
                                    new_qty=tag.total_pcs,
                                    change_qty=-qty_to_take_from_tag,
                                    user=request.user if request.user.is_authenticated else None,
                                    notes=f"PICKING: Issued for Request {req_no}"
                                )
                                
                                qty_needed -= qty_to_take_from_tag

                            # Defense: Baka kulang pala talaga ang stock sa buong warehouse!
                            if qty_needed > 0:
                                raise Exception(f"Insufficient stock in warehouse for {req_item.item_code}. Missing {qty_needed} pcs.")

                            # 3. I-update ang Request Item (Idagdag sa nai-deliver na)
                            req_item.delivered_qty += qty_to_pick
                            req_item.save()
                            total_picked_items += 1

                    # Check for completion of this line item
                    if req_item.delivered_qty < req_item.request_qty:
                        all_items_completed = False

                # 4. Update Header Status
                if total_picked_items > 0:
                    inv_request.status = 'Completed' if all_items_completed else 'Processing'
                    inv_request.save()
                    
                    log_system_action(
                        user=request.user, 
                        action='UPDATE', 
                        module='Order Picking', 
                        description=f"Processed {total_picked_items} items for Request {req_no}. Status: {inv_request.status}", 
                        request=request
                    )
                    messages.success(request, f"Success! Picking for Request {req_no} has been registered and deducted from stock (FIFO).")
                else:
                    messages.warning(request, "No items were picked. Quantities must be greater than 0.")

        except Exception as e:
            messages.error(request, f"Error processing picking: {str(e)}")
        return redirect('ri_picking') 

    # GET Request
    locations = LocationMaster.objects.all().order_by('zone', 'location_code')
    return render(request, 'Inventory/receiving/RI_picking.html', {'locations': locations})

@login_required
@require_module_access('RECEIVING')
def picking_list_print_view(request, req_no):
    try:
        header = get_object_or_404(DeliveryRequest, request_no=req_no)
        items = header.items.all()
        
        # Kukunin natin ang available stock per item para makita sa printout
        from django.db.models import Sum
        items_with_stock = []
        for item in items:
            stock = MaterialTag.objects.filter(item_code=item.item_code, total_pcs__gt=0).aggregate(Sum('total_pcs'))['total_pcs__sum'] or 0
            item.current_stock = stock
            items_with_stock.append(item)

        context = {
            'header': header,
            'items': items_with_stock,
            'now': datetime.datetime.now(),
        }
        return render(request, 'Inventory/receiving/picking_list_print.html', context)
    except Exception as e:
        messages.error(request, f"Error generating picking list: {str(e)}")
        return redirect('ri_picking')

@login_required
def get_picking_list(request):
    """Kinukuha ang Request items at ang current stock level nila."""
    req_no = request.GET.get('req_no', '').strip()
    
    if not req_no:
        return JsonResponse({'success': False, 'error': 'No Request No. scanned.'})

    # 🚀 BAGO: Safe na paghahanap
    del_request = DeliveryRequest.objects.filter(request_no=req_no).first()
    
    if not del_request:
        return JsonResponse({'success': False, 'error': f'Request {req_no} not found!'})

    if del_request.status == 'Completed':
        return JsonResponse({'success': False, 'error': f'Request {req_no} is already Completed!'})

    items_data = []
    
    for index, item in enumerate(del_request.items.all(), start=1): 
        remaining_qty = item.request_qty - item.delivered_qty
        
        if remaining_qty <= 0:
            continue
            
        from django.db.models import Sum
        # from Inventory.models import Item # Tinanggal ko ang import dito para iwas circular import error. Siguraduhin na naka-import ito sa taas ng views.py mo.

        total_available = MaterialTag.objects.filter(
            item_code=item.item_code, total_pcs__gt=0
        ).aggregate(Sum('total_pcs'))['total_pcs__sum'] or 0

        item_master = Item.objects.filter(item_code=item.item_code).first()

        current_price = getattr(item, 'unit_price', (item_master.unit_price if item_master else 0.00))

        items_data.append({
            'no': index,
            'item_id': item.id,
            'item_code': item.item_code,
            'description': item.description or 'No Description',
            'revision': item.revision if item.revision else '', 
            'request_qty': item.request_qty,
            'delivered_qty': item.delivered_qty,
            'remaining_qty': remaining_qty,
            'available_stock': total_available,
            'unit_price': float(current_price), 
        })

    if not items_data:
        return JsonResponse({'success': False, 'error': f'All items in {req_no} have already been picked/delivered.'})

    return JsonResponse({
        'success': True,
        'req_no': del_request.request_no, 
        'delivery_place': del_request.delivery_place,
        'items': items_data
    })

@login_required
@require_module_access('RECEIVING')
def process_picking_scan(request):
    """Pinoproseso ang pag-scan ng Material Tag at pagbawas sa stock."""
    if request.method == 'POST':
        lot_no = request.POST.get('lot_no', '').strip().upper()
        req_no = request.POST.get('req_no', '').strip()
        pick_qty = int(request.POST.get('pick_qty', 0))

        try:
            with transaction.atomic():
                tag = MaterialTag.objects.get(lot_no=lot_no)
                
                if tag.total_pcs < pick_qty:
                    return JsonResponse({'success': False, 'error': f'Not enough stock in Lot {lot_no}. Available: {tag.total_pcs}'})

                # Bawasan ang stock sa Material Tag
                tag.total_pcs -= pick_qty
                tag.save()

                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Order Picking', 
                    description=f"Deducted {pick_qty} PCS from Lot {lot_no} for Request {req_no}.", 
                    request=request
                )

                # Dito pwede mong i-update ang picked_qty ng DeliveryRequestItem mo
                # del_item = DeliveryRequestItem.objects.get(...)
                # del_item.picked_qty += pick_qty
                # del_item.save()

                return JsonResponse({
                    'success': True, 
                    'message': f'Successfully picked {pick_qty} PCS from {lot_no}!',
                    'item_code': tag.item_code,
                    'remaining': tag.total_pcs
                })
        except MaterialTag.DoesNotExist:
            return JsonResponse({'success': False, 'error': f'Material Tag (Lot: {lot_no}) not found!'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'Invalid request'})

@login_required
@require_module_access('INV_PROCESSING')
def stock_move_view(request):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        new_loc_code = request.POST.get('new_location')

        try:
            with transaction.atomic(): # 🚀 Idinagdag para safe ang database
                tag = MaterialTag.objects.get(id=tag_id)
                
                # Kunin o gumawa ng bagong location
                new_location, _ = LocationMaster.objects.get_or_create(location_code=new_loc_code.upper())
                
                old_loc = tag.location.location_code if tag.location else "UNASSIGNED"
                
                # Defense: Baka nandoon na pala siya!
                if old_loc == new_location.location_code:
                    messages.warning(request, f"Item is already in {new_location.location_code}. No movement recorded.")
                    return redirect('stock_move')

                # I-update ang location
                tag.location = new_location
                tag.save()

                # 🚀 BAGO: Kailangan nating i-log ito sa StockLog para may history!
                StockLog.objects.create(
                    material_tag=tag,
                    action_type='MOVE',
                    old_qty=tag.total_pcs,
                    new_qty=tag.total_pcs,
                    change_qty=0, # Walang nagbago sa bilang
                    notes=f"QUICK MOVE: From {old_loc} to {new_location.location_code}",
                    user=request.user if request.user.is_authenticated else None
                )

                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Inventory Movement', 
                    description=f"Moved Lot {tag.lot_no} from {old_loc} to {new_location.location_code}.", 
                    request=request
                )

                try:
                    send_stock_move_alert(tag, old_loc, new_location.location_code, request.user)
                except Exception as e:
                    print(f"Stock Move Email Error: {e}")

                messages.success(request, f"Success! {tag.lot_no} moved from {old_loc} to {new_location.location_code}.")
                return redirect('stock_move')
                
        except MaterialTag.DoesNotExist:
            messages.error(request, "Error: Material Tag not found!")
        except Exception as e:
            messages.error(request, f"Error processing Stock Move: {str(e)}")
            
        return redirect('stock_move')

    # GET Request (Load page)
    locations = LocationMaster.objects.all().order_by('warehouse', 'zone', 'location_code')
    
    return render(request, 'Inventory/processing/stock_move.html', {'locations': locations})

@login_required
def get_tag_info(request):
    """
    Ito ang sumasalo ng scan mula sa Stock Move, Stock Out, at Stock Correction.
    Nagbabalik ito ng JSON data papunta sa Javascript ng frontend.
    """
    lot_no_query = request.GET.get('lot_no', '').strip()

    if not lot_no_query:
        return JsonResponse({'success': False, 'error': 'No barcode scanned.'})

    try:
        tag = MaterialTag.objects.get(lot_no=lot_no_query)
        current_loc = "Unassigned / No Location"
        
        if tag.location:
            try:
                current_loc = tag.location.location_code
                if hasattr(tag.location, 'zone') and tag.location.zone:
                    current_loc = f"{tag.location.location_code} | {tag.location.zone}"
            except Exception:
                current_loc = "Location Format Error"

        data = {
            'success': True,
            'tag_id': tag.id,
            'item_code': tag.item_code,
            'description': tag.description if tag.description else "No description",
            'current_qty': tag.total_pcs,
            'current_location': current_loc,
            'lot_no': tag.lot_no,
        }
        return JsonResponse(data)

    except MaterialTag.DoesNotExist:
        return JsonResponse({'success': False, 'error': f'Barcode {lot_no_query} not found in inventory.'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Server Error: {str(e)}'})

@login_required
@require_module_access('INV_PROCESSING')
def stock_correction_view(request):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        new_qty_str = request.POST.get('new_qty')
        new_loc_code = request.POST.get('new_location', '').strip().upper()
        reason = request.POST.get('reason', 'Correction')

        if not tag_id or not new_qty_str:
            messages.error(request, "System Error: Missing Tag ID or Quantity.")
            return redirect('stock_correction')

        try:
            with transaction.atomic(): # Protect the database
                tag = MaterialTag.objects.get(id=tag_id)
                old_qty = tag.total_pcs
                old_loc = tag.location.location_code if tag.location else "UNASSIGNED"
                new_qty = int(new_qty_str)
                change_in_qty = new_qty - old_qty

                # 1. Update Quantity
                tag.total_pcs = new_qty

                # 2. Update Location
                new_loc_str = old_loc 
                if new_loc_code and new_loc_code != old_loc:
                    new_location, _ = LocationMaster.objects.get_or_create(location_code=new_loc_code)
                    tag.location = new_location
                    new_loc_str = new_location.location_code

                tag.save()

                # 3. I-save sa StockLog
                notes = f"CORRECTION: Reason -> {reason}"
                if new_loc_str != old_loc:
                    notes += f" | Moved {old_loc} -> {new_loc_str}"

                StockLog.objects.create(
                    material_tag=tag,
                    action_type='CORR', 
                    old_qty=old_qty,
                    new_qty=new_qty,
                    change_qty=change_in_qty,
                    notes=notes,
                    user=request.user if request.user.is_authenticated else None
                )

                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Inventory Control', 
                    description=f"Corrected Lot {tag.lot_no}. QTY: {old_qty}->{new_qty}. LOC: {old_loc}->{new_loc_str}. Reason: {reason}", 
                    request=request
                )

                # Optional: Kung may alert functions ka, make sure imported sila
                try:
                    alert_stock_correction(tag, old_qty, new_qty, reason, request.user)
                except NameError:
                    pass # Ignore kung wala pa yung function na to

                messages.success(request, f"Correction Saved! {tag.lot_no} updated. QTY: {old_qty} -> {new_qty} | LOC: {old_loc} -> {new_loc_str}.")
                return redirect('stock_correction')
                
        except MaterialTag.DoesNotExist:
             messages.error(request, "Error: Material Tag not found in database.")
        except Exception as e:
             messages.error(request, f"Error processing Stock Correction: {str(e)}")
             
        return redirect('stock_correction')

    locations = LocationMaster.objects.all().order_by('warehouse', 'zone', 'location_code')

    return render(request, 'Inventory/processing/stock_correction.html', {'locations': locations})

@login_required
@require_module_access('INV_PROCESSING')
def stock_out_view(request):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        qty_to_deduct_str = request.POST.get('qty_out')
        remarks = request.POST.get('remarks', 'Stock Out').strip()

        if not tag_id or not qty_to_deduct_str:
            messages.error(request, "System Error: Missing Tag ID or Quantity.")
            return redirect('stock_out')

        try:
            with transaction.atomic(): 
                tag = MaterialTag.objects.get(id=tag_id)
                deduct_val = int(qty_to_deduct_str)
                old_qty = tag.total_pcs

                if deduct_val <= 0:
                     messages.error(request, "Error: Deduction quantity must be greater than zero.")
                elif deduct_val > old_qty:
                    messages.error(request, f"Error: Cannot deduct {deduct_val} pcs. Only {old_qty} pcs remaining in Lot {tag.lot_no}.")
                else:
                    tag.total_pcs -= deduct_val
                    new_qty = tag.total_pcs
                    tag.save()

                    StockLog.objects.create(
                        material_tag=tag,
                        action_type='OUT', 
                        old_qty=old_qty,
                        new_qty=new_qty,
                        change_qty=-deduct_val, 
                        notes=f"ISSUANCE: {remarks}",
                        user=request.user if request.user.is_authenticated else None
                    )

                    log_system_action(
                        user=request.user, 
                        action='UPDATE', 
                        module='Inventory Issuance', 
                        description=f"Stock Out: Deducted {deduct_val} PCS from Lot {tag.lot_no}. Remarks: {remarks}", 
                        request=request
                    )
                    
                    # Optional: Check low stock alert
                    try:
                        send_stock_out_alert(tag, deduct_val, new_qty, remarks, request.user)
                    except Exception as e:
                        print(f"Stock Out Email Error: {e}")
                    
                    messages.success(request, f"Success! Deducted {deduct_val} pcs from {tag.lot_no}. Remaining: {new_qty} pcs.")
                    return redirect('stock_out') 
                
        except MaterialTag.DoesNotExist:
             messages.error(request, "Error: Material Tag not found in database.")
        except ValueError:
             messages.error(request, "Error: Invalid quantity entered.")
        except Exception as e:
            messages.error(request, f"Error processing Stock Out: {str(e)}")
            
        return redirect('stock_out')

    # 🚀 FIX: Tinuturo na ito sa bagong "processing" folder
    return render(request, 'Inventory/processing/stock_out.html')

@login_required
@require_module_access('INV_INQUIRY')
def stock_inquiry_view(request):
    stocks = MaterialTag.objects.select_related('po_reference', 'po_reference__supplier', 'location').all().order_by('-arrival_date')

    inquiry_type = request.GET.get('inquiry_type', 'current')
    company = request.GET.get('company', '').strip()
    item_code = request.GET.get('item_code', '').strip()
    description = request.GET.get('description', '').strip()
    lot_no = request.GET.get('lot_no', '').strip()
    location_search = request.GET.get('location', '').strip()

    if inquiry_type == 'current':  
        stocks = stocks.filter(total_pcs__gt=0) 
    elif inquiry_type == 'out':
        stocks = stocks.filter(total_pcs__lte=0)
        
    if company:
        stocks = stocks.filter(po_reference__supplier__name__icontains=company)
    if item_code:
        stocks = stocks.filter(item_code__icontains=item_code)
    if description:
        stocks = stocks.filter(description__icontains=description)
    if lot_no:
        stocks = stocks.filter(lot_no__icontains=lot_no)
    if location_search:
        from django.db.models import Q
        stocks = stocks.filter(
            Q(location__location_code__icontains=location_search) | 
            Q(location__zone__icontains=location_search)
        )

    total_active_tags = stocks.filter(total_pcs__gt=0).count()
    total_qty_stock = stocks.filter(total_pcs__gt=0).aggregate(total=Sum('total_pcs'))['total'] or 0
    out_of_stock_tags = stocks.filter(total_pcs__lte=0).count()

    if request.GET.get('export_excel') == 'true':
        all_item_codes = stocks.values_list('item_code', flat=True).distinct()
        item_prices = dict(Item.objects.filter(item_code__in=all_item_codes).values_list('item_code', 'unit_price'))
        
        data = []
        for s in stocks:
            u_price = item_prices.get(s.item_code, 0.00)
            data.append({
                'Label No.': f"TAG-{s.id:05d}",
                'Item Code': s.item_code,
                'Item Name': s.description,
                'Company': s.po_reference.supplier.name if s.po_reference and s.po_reference.supplier else 'INTERNAL',
                'Warehouse': s.location.zone if s.location else 'Main Warehouse',
                'Location': s.location.location_code if s.location else '',
                'Lot No.': s.lot_no,
                'Status': s.inspection_status,
                'PO No.': s.po_reference.po_no if s.po_reference else '',
                'Invoice No.': s.invoice_no if s.invoice_no else '',
                'Revision': s.revision if s.revision else '',
                'Receipt Date': s.arrival_date.strftime('%Y-%m-%d') if s.arrival_date else '',
                'Expiry Date': s.expiration_date.strftime('%Y-%m-%d') if s.expiration_date else '',
                'Quantity': s.total_pcs,
                'Unit': s.packing_type,
                'Unit Price': float(u_price),
            })

        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="Stock_Masterlist_Export.xlsx"'

        with pd.ExcelWriter(response, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Inventory Data')
            worksheet = writer.sheets['Inventory Data']
            for column_cells in worksheet.columns:
                length = max(len(str(cell.value)) for cell in column_cells)
                worksheet.column_dimensions[column_cells[0].column_letter].width = length + 2

        return response

    paginator = Paginator(stocks, 20) 
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    page_item_codes = [s.item_code for s in page_obj.object_list]
    page_item_prices = dict(Item.objects.filter(item_code__in=page_item_codes).values_list('item_code', 'unit_price'))
    for s in page_obj.object_list:
        s.unit_price = page_item_prices.get(s.item_code, 0.00)

    context = {
        'page_obj': page_obj,
        'total_active_tags': total_active_tags,
        'total_qty_stock': total_qty_stock,
        'out_of_stock_tags': out_of_stock_tags,
        'inquiry_type': inquiry_type,
        'company': company,
        'item_code': item_code,
        'description': description,
        'lot_no': lot_no,
        'location_search': location_search, 
        'today': timezone.now().date(),
    }
    # 🚀 FIX: Itinuro sa inventory_inquiry folder
    return render(request, 'Inventory/inventory_inquiry/stock_inquiry.html', context)

@login_required
@require_module_access('INV_INQUIRY')
def stock_io_view(request, tag_id):
    stock = get_object_or_404(MaterialTag, id=tag_id)
    history_logs = stock.logs.all().order_by('-timestamp')
    total_in = sum(log.change_qty for log in history_logs if log.change_qty > 0)
    total_out = sum(abs(log.change_qty) for log in history_logs if log.change_qty < 0)
    context = {
        'stock': stock,
        'history_logs': history_logs,
        'total_in': total_in,
        'total_out': total_out,
    }
    return render(request, 'Inventory/inventory_inquiry/stock_io_history.html', context)

@login_required
@require_module_access('INV_INQUIRY')
def api_update_item_price(request):
    if request.method == 'POST':
        item_code = request.POST.get('item_code', '').strip()
        new_price = request.POST.get('unit_price', 0)
        try:
            item = Item.objects.get(item_code=item_code)
            item.unit_price = float(new_price)
            item.save()
            return JsonResponse({'success': True})
        except Item.DoesNotExist:
            return JsonResponse({'success': False, 'error': f'Item {item_code} not found in Masterlist.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid Request'})

@login_required
@require_module_access('INV_INQUIRY')
def api_update_tag_details(request):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        field = request.POST.get('field')
        value = request.POST.get('value', '').strip()

        try:
            tag = MaterialTag.objects.get(id=tag_id)
            
            if field == 'lot_no':
                tag.lot_no = value
            elif field == 'revision':
                tag.revision = value
            elif field == 'invoice_no':
                tag.invoice_no = value
            elif field == 'expiration_date':
                # Kung blangko ang pinasa, ibig sabihin tinanggal ang date
                tag.expiration_date = value if value else None
                
            tag.save()
            return JsonResponse({'success': True})
            
        except MaterialTag.DoesNotExist:
            return JsonResponse({'success': False, 'error': f'Tag ID {tag_id} not found.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'Invalid Request'})

@login_required
@require_module_access('INV_INQUIRY')
def stock_item_inquiry_view(request):
    search_query = request.GET.get('q', '').strip()
    
    # 🚀 BAGO: Dito na natin ginrupo gamit ang PAREHONG Item Code at Description!
    # Magkakasunod din sila sa table (order_by) para napakalinaw sa mata.
    inventory = MaterialTag.objects.values('item_code', 'description').annotate(
        total_stock=Sum('total_pcs'),
        lot_count=Count('id')
    ).order_by('item_code', 'description')

    if search_query:
        inventory = inventory.filter(
            Q(item_code__icontains=search_query) | 
            Q(description__icontains=search_query)
        )

    # 🚀 EXPORT TO EXCEL NG GLOBAL SUMMARY
    if request.GET.get('export_excel') == 'true':
        data = []
        for item in inventory:
            data.append({
                'Item Code': item['item_code'],
                'Description': item['description'],
                'Total Number of Lots': item['lot_count'],
                'Total Available Stock': item['total_stock'] or 0,
            })
        
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="Global_Inventory_Summary.xlsx"'
        
        with pd.ExcelWriter(response, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Global Summary')
            worksheet = writer.sheets['Global Summary']
            for column_cells in worksheet.columns:
                length = max(len(str(cell.value)) for cell in column_cells)
                worksheet.column_dimensions[column_cells[0].column_letter].width = length + 2
                
        return response

    sys_settings = SystemSetting.objects.first()
    actual_threshold = sys_settings.low_stock_threshold if sys_settings else 50

    paginator = Paginator(inventory, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'items': page_obj,
        'search_query': search_query,
        'settings': {
            'low_stock_threshold': actual_threshold 
        }
    }
    
    return render(request, 'Inventory/inventory_inquiry/stock_item_inquiry.html', context)

@login_required
@require_module_access('INV_INQUIRY')
def stock_history_view(request):
    logs = StockLog.objects.select_related('material_tag', 'user').all().order_by('-timestamp')

    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    action_type = request.GET.get('action_type')
    item_code = request.GET.get('item_code')
    lot_no = request.GET.get('lot_no')

    if date_from:
        logs = logs.filter(timestamp__date__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__date__lte=date_to)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if item_code:
        logs = logs.filter(material_tag__item_code__icontains=item_code)
    if lot_no:
        logs = logs.filter(material_tag__lot_no__icontains=lot_no)

    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    query_dict = request.GET.copy()
    if 'page' in query_dict:
        del query_dict['page']
    filter_params = query_dict.urlencode()

    context = {
        'logs': page_obj,
        'filter_params': filter_params, 
    }
    # 🚀 FIX: Itinuro sa inventory_inquiry folder
    return render(request, 'Inventory/inventory_inquiry/stock_history.html', context)

@login_required
@require_module_access('INV_INQUIRY')
def request_inquiry_view(request):
    requests_data = DeliveryRequest.objects.annotate(
        item_count=Count('items'),
        total_qty=Sum('items__request_qty')
    ).order_by('-request_date', '-request_no')
        
    req_no = request.GET.get('req_no')
    status = request.GET.get('status')
    department = request.GET.get('department')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')

    if req_no:
        requests_data = requests_data.filter(request_no__icontains=req_no)
    if status:
        requests_data = requests_data.filter(status=status)
    if department:
        requests_data = requests_data.filter(receiving_place__icontains=department)
    if date_from:
        requests_data = requests_data.filter(request_date__gte=date_from)
    if date_to:
        requests_data = requests_data.filter(request_date__lte=date_to)

    paginator = Paginator(requests_data, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'requests': page_obj,
    }
    # 🚀 FIX: Itinuro sa inventory_inquiry folder
    return render(request, 'Inventory/inventory_inquiry/request_inquiry.html', context)

@login_required
@require_module_access('INV_INQUIRY')
def inquiry_settings_view(request):
    system_settings, created = SystemSetting.objects.get_or_create(id=1)

    if request.method == 'POST':
        low_stock_limit = request.POST.get('low_stock_limit')
        items_per_page = request.POST.get('items_per_page')
        email_alerts = request.POST.get('email_alerts') 
        
        try:
            if low_stock_limit and low_stock_limit.isdigit():
                system_settings.low_stock_threshold = int(low_stock_limit)
            
            system_settings.enable_email_alerts = True if email_alerts == 'on' else False
            system_settings.save()
            
            if items_per_page and items_per_page.isdigit():
                request.session['items_per_page'] = int(items_per_page)

            log_system_action(
                user=request.user, 
                action='UPDATE', 
                module='System Settings', 
                description=f"Updated Global Settings. Low Stock Threshold set to {system_settings.low_stock_threshold}.", 
                request=request
            )

            messages.success(request, "System Preferences updated successfully! Settings are now active across the WMS.")
            return redirect('inquiry_settings')

        except Exception as e:
            messages.error(request, f"Failed to save settings: {str(e)}")
            return redirect('inquiry_settings')

    context = {
        'low_stock_limit': system_settings.low_stock_threshold,
        'email_alerts_enabled': system_settings.enable_email_alerts,
        'items_per_page': request.session.get('items_per_page', 50), 
    }
    # 🚀 FIX: Itinuro sa inventory_inquiry folder
    return render(request, 'Inventory/inventory_inquiry/inquiry_settings.html', context)

def shipment_import_view(request):
    if request.method == "POST":
        if 'excel_file' in request.FILES:
            excel_file = request.FILES['excel_file']
            
            # Defense: Check kung excel o csv
            if not excel_file.name.endswith(('.xlsx', '.xls', '.csv')):
                messages.error(request, "Invalid file format. Please upload an Excel (.xlsx) or CSV file.")
                return redirect('shipment_import')
                
            try:
                # 1. Basahin ang file gamit ang Pandas
                if excel_file.name.endswith('.csv'):
                    df = pd.read_csv(excel_file)
                else:
                    df = pd.read_excel(excel_file, engine='openpyxl')
                
                # Tanggalin ang mga empty rows para iwas error
                df = df.dropna(how='all')
                
                saved_count = 0
                
                # 🚀 2. THE DATABASE SAVING LOGIC
                # Gagamit tayo ng transaction.atomic() para kung may mag-error sa gitna,
                # ire-roll back niya lahat at hindi masisira ang database mo.
                with transaction.atomic():
                    for index, row in df.iterrows():
                        
                        # A. Hanapin o i-register ang Supplier
                        supplier_name = str(row.get('Supplier', 'Unknown Supplier')).strip()
                        supplier_obj, created = Contact.objects.get_or_create(
                            name=supplier_name,
                            defaults={'contact_type': 'Supplier'} # Assuming Contact table gamit mo
                        )
                        
                        # B. Ayusin ang Delivery Date format
                        raw_date = row.get('Delivery_Date', None)
                        del_date = None
                        if pd.notna(raw_date):
                            try:
                                del_date = pd.to_datetime(raw_date).date()
                            except:
                                pass
                                
                        # C. I-save as PurchaseOrder Item
                        # ⚠️ PAALALA: Kung 'qty' o 'total_pcs' ang gamit mo sa models.py imbes na 'quantity',
                        # palitan mo lang yung salitang 'quantity=' sa ibaba.
                        PurchaseOrder.objects.create(
                            po_no=str(row.get('PO_No', '')).strip(),
                            supplier=supplier_obj,
                            delivery_date=del_date,
                            ordering_status=str(row.get('Status', 'Approved')).strip(),
                            item_code=str(row.get('Item_Code', '')).strip(),
                            description=str(row.get('Description', '')).strip(),
                            
                            # Dito kumukuha ng values sa CSV columns:
                            quantity=row.get('Qty', 0), 
                            unit_price=row.get('Unit_Price', 0.0),
                            amount=float(row.get('Qty', 0)) * float(row.get('Unit_Price', 0.0))
                        )
                        saved_count += 1
                
                # System Log
                log_system_action(
                    user=request.user, 
                    action='CREATE', 
                    module='Inbound Shipment', 
                    description=f"Imported Shipment Schedule via Excel: {excel_file.name} ({row_count} rows)", 
                    request=request
                )
                
                messages.success(request, f"Success! {saved_count} items from {excel_file.name} successfully imported and scheduled.")
                return redirect('shipment_inquiry')
                
            except Exception as e:
                print(f"IMPORT ERROR: {str(e)}")
                messages.error(request, f"Error saving to database: {str(e)}. Please make sure your column names exactly match the template.")
                return redirect('shipment_import')
        else:
            messages.warning(request, "Please select a file to upload.")
            return redirect('shipment_import')

    # GET Request
    return render(request, 'Inventory/inbound/shipment_import.html')

def shipment_inquiry_view(request):
    search_query = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '').strip()
    
    # 1. Kunin lahat ng P.O. na active at paparating pa lang
    qs = PurchaseOrder.objects.exclude(
        ordering_status__in=['Cancelled', 'Received']
    ).order_by('delivery_date', '-id') # Naka-sort sa pinaka-malapit na delivery date
    
    if search_query:
        qs = qs.filter(
            Q(po_no__icontains=search_query) |
            Q(supplier__name__icontains=search_query)
        )
        
    if status_filter:
        qs = qs.filter(ordering_status=status_filter)

    # 2. I-Group by PO Number (Dahil pwedeng multiple items per PO)
    po_dict = {}
    overall_inbound_value = 0.0
    today = timezone.now().date()
    
    for item in qs:
        po_no = item.po_no
        
        if po_no not in po_dict:
            po_dict[po_no] = {
                'header': {
                    'po_no': po_no,
                    'supplier': item.supplier.name if getattr(item, 'supplier', None) else 'Unknown Supplier',
                    'order_date': getattr(item, 'order_date', None),
                    'delivery_date': getattr(item, 'delivery_date', None),
                    'status': getattr(item, 'ordering_status', 'Pending'),
                    'remarks': getattr(item, 'remarks', ''),
                    'grand_total': 0.0,
                },
                'items': []
            }
            
        # 🚀 THE BULLETPROOF FIX: Hahanapin natin kung nasaan ang laman ng PO
        
        # SCENARIO A: Kung may related table ka para sa items (e.g., po.items.all())
        if hasattr(item, 'items') and callable(getattr(item.items, 'all', None)):
            po_lines = item.items.all()
            for line in po_lines:
                po_dict[po_no]['items'].append(line)
                
                # Dynamic Check: Hahanapin kung 'quantity' o 'qty' ang name sa models mo
                qty = getattr(line, 'quantity', getattr(line, 'qty', 0))
                price = getattr(line, 'unit_price', getattr(line, 'price', 0))
                amount = getattr(line, 'amount', float(qty or 0) * float(price or 0))
                
                po_dict[po_no]['header']['grand_total'] += float(amount)
                overall_inbound_value += float(amount)
                
        # SCENARIO B: Kung Flat Table ka (Isang table lang lahat)
        else:
            po_dict[po_no]['items'].append(item)
            
            # Dynamic Check din dito
            qty = getattr(item, 'quantity', getattr(item, 'qty', 0))
            price = getattr(item, 'unit_price', getattr(item, 'price', 0))
            amount = getattr(item, 'amount', float(qty or 0) * float(price or 0))
            
            po_dict[po_no]['header']['grand_total'] += float(amount)
            overall_inbound_value += float(amount)

    po_list = list(po_dict.values())
    
    # 3. Compute Top Level Summary Cards
    total_shipments = len(po_list)
    total_delayed = sum(1 for p in po_list if p['header']['delivery_date'] and p['header']['delivery_date'] < today and p['header']['status'] not in ['Shipped', 'In Transit'])
    total_in_transit = sum(1 for p in po_list if p['header']['status'] in ['Shipped', 'In Transit'])

    # 4. Pagination
    paginator = Paginator(po_list, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'items': page_obj, 
        'search_query': search_query,
        'status_filter': status_filter,
        'overall_inbound_value': overall_inbound_value,
        'total_shipments': total_shipments,
        'total_delayed': total_delayed,
        'total_in_transit': total_in_transit,
    }
    
    return render(request, 'Inventory/inbound/shipment_inquiry.html', context)

# 1. VIEW PARA SA CALENDAR (Calendar View ng Inbound at Outbound Shipments)
@login_required
def shipment_calendar_view(request):
    today = date.today()
    
    # 1. Kukunin natin lahat ng PO na HINDI PA "Received" o "Cancelled"
    active_pos = PurchaseOrder.objects.exclude(
        ordering_status__in=['Received', 'Cancelled']
    ).prefetch_related('items', 'supplier')

    events_data = []
    late_deliveries = []

    for po in active_pos:
        # Kung walang delivery date, skip natin sa calendar
        if not po.delivery_date: 
            continue

        # 2. Compute Late Days
        days_late = (today - po.delivery_date).days
        is_late = days_late > 0

        # 3. I-compile ang mga items para sa Modal
        item_list = []
        for item in po.items.all():
            item_list.append({
                'code': item.item_code,
                'desc': item.description or 'No Description',
                'qty': item.qty,
                'uom': getattr(item, 'uom', 'PCS') # Fallback to PCS if uom doesn't exist on item
            })

        # 4. Buuin ang Event Data para sa Calendar
        events_data.append({
            'id': po.po_no,
            'title': f"IN: {po.po_no}",
            'start': po.delivery_date.strftime('%Y-%m-%d'),
            # BONUS: RED kapag late, BLUE kapag on-time!
            'backgroundColor': '#ef4444' if is_late else '#2563eb', 
            'borderColor': '#b91c1c' if is_late else '#1d4ed8',
            'extendedProps': {
                'supplier': po.supplier.name if po.supplier else 'Unknown Supplier',
                'status': po.ordering_status,
                'is_late': is_late,
                'days_late': days_late,
                'items': item_list
            }
        })

        # 5. Ipunin ang mga Late Deliveries para sa Dropdown Table
        if is_late:
            late_deliveries.append({
                'po_no': po.po_no,
                'supplier': po.supplier.name if po.supplier else 'Unknown',
                'expected_date': po.delivery_date,
                'days_late': days_late,
                'status': po.ordering_status
            })

    # Sort natin yung late deliveries para yung pinaka-late ang nasa pinakataas
    late_deliveries.sort(key=lambda x: x['days_late'], reverse=True)

    context = {
        'events_json': json.dumps(events_data), # Ipasa bilang JSON sa Javascript
        'late_deliveries': late_deliveries,
        'late_count': len(late_deliveries)
    }
    
    return render(request, 'Inventory/inbound/shipment_calendar.html', context)

# 1. API para makuha ang details ng isang shipment (Para sa Inquiry Button)
def api_shipment_details(request, ship_id):
    try:
        shipment = ShipmentSchedule.objects.get(id=ship_id)
        data = {
            'shipment_no': shipment.shipment_no,
            'customer': shipment.customer.name if shipment.customer else 'N/A',
            'item_code': shipment.item_code,
            'quantity': shipment.quantity,
            'schedule_date': shipment.schedule_date.strftime('%Y-%m-%d'),
            'transport': shipment.transport or 'Not Set',
            'invoice_no': shipment.invoice_no or 'Not Set',
            'destination': shipment.destination,
            'status': shipment.status,
        }
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

# 2. Function para sa pag-update ng Shipment (Para sa Update Button)
def shipment_update(request):
    if request.method == 'POST':
        ship_id = request.POST.get('ship_id')
        shipment = ShipmentSchedule.objects.get(id=ship_id)
        
        shipment.schedule_date = request.POST.get('schedule_date')
        shipment.transport = request.POST.get('transport')
        shipment.invoice_no = request.POST.get('invoice_no')
        shipment.save()
        
        messages.success(request, f"Shipment {shipment.shipment_no} updated successfully.")
        return redirect('shipment_inquiry')

def shipment_allocation_view(request, po_no):
    po_items = PurchaseOrder.objects.filter(po_no=po_no)
    
    if not po_items.exists():
        messages.error(request, f"Purchase Order {po_no} not found.")
        return redirect('shipment_inquiry')
        
    first_item = po_items.first()
    
    actual_items = []
    if hasattr(first_item, 'items') and callable(getattr(first_item.items, 'all', None)):
        actual_items = list(first_item.items.all())
    else:
        actual_items = list(po_items)

    # ==========================================
    # KUNG I-SU-SUBMIT NA NG GUARD ANG DOCK ARRIVAL
    # ==========================================
    if request.method == "POST":
        try:
            with transaction.atomic():
                guard_time = request.POST.get('guard_time', '')
                dock_remarks = request.POST.get('dock_remarks', '')
                
                total_boxes = 0
                item_details_log = []

                # I-loop ang items
                for item in actual_items:
                    item_id = str(item.id)
                    actual_qty_str = request.POST.get(f'actual_qty_{item_id}', '0')
                    box_count_str = request.POST.get(f'box_count_{item_id}', '0')
                    condition = request.POST.get(f'condition_{item_id}', 'GOOD')
                    
                    actual_qty = float(actual_qty_str) if actual_qty_str else 0.0
                    box_count = int(box_count_str) if box_count_str else 0
                    
                    total_boxes += box_count
                    item_details_log.append(f"{item.item_code}: {box_count} boxes ({condition})")
                    
                    # I-save sa CONFIRMED_QTY ang bilang sa dock
                    if hasattr(item, 'confirmed_qty'):
                        item.confirmed_qty = actual_qty
                        item.save()

                # 🚀 UPDATE PO HEADER TO 'Approved'
                # Para pag in-scan nila sa Receiving, PASOK AGAD!
                combined_remarks = f"Arrived at Gate @ {guard_time}. Total Handling Units: {total_boxes} Boxes. Remarks: {dock_remarks}"
                
                po_items.update(
                    ordering_status='Approved', 
                    remarks=combined_remarks
                )
                
                # SYSTEM AUDIT LOG (Pang-depensa sa Audit)
                SystemAuditLog.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    action='UPDATE',
                    module='Dock Arrival',
                    description=f"PO {po_no} approved for Receiving. Details: {', '.join(item_details_log)}"
                )
                
            messages.success(request, f"Success! {total_boxes} boxes arrived at the dock. Shipment {po_no} is now Approved for Receiving.")
            return redirect('shipment_inquiry')
            
        except Exception as e:
            messages.error(request, f"System Error: {str(e)}")
            return redirect('shipment_allocation', po_no=po_no)

    # PREPARE DATA FOR HTML
    for item in actual_items:
        item.safe_qty = getattr(item, 'quantity', getattr(item, 'qty', getattr(item, 'total_pcs', 0)))
        item.safe_code = getattr(item, 'item_code', None) or (item.item.item_code if hasattr(item, 'item') else 'N/A')
        item.safe_desc = getattr(item, 'description', None) or (item.item.description if hasattr(item, 'item') else '-')
        
    context = {
        'po_no': po_no,
        'supplier_name': first_item.supplier.name if getattr(first_item, 'supplier', None) else 'Unknown Supplier',
        'po_items': actual_items,
        'first_item': first_item,
        'current_time': timezone.now().strftime('%H:%M'),
    }
    
    return render(request, 'Inventory/inbound/shipment_allocation.html', context)

def shipment_print_doc_view(request, po_no):
    po_qs = PurchaseOrder.objects.filter(po_no=po_no)
    
    if not po_qs.exists():
        messages.error(request, f"Purchase Order {po_no} not found.")
        return redirect('shipment_inquiry')
        
    first_item = po_qs.first()
    
    # 🚀 BULLETPROOF ITEM EXTRACTION
    actual_items = []
    if hasattr(first_item, 'items') and callable(getattr(first_item.items, 'all', None)):
        actual_items = list(first_item.items.all())
    else:
        actual_items = list(po_qs)

    grand_total = 0.0
    for item in actual_items:
        qty = getattr(item, 'quantity', getattr(item, 'qty', getattr(item, 'total_pcs', 0)))
        price = getattr(item, 'unit_price', getattr(item, 'price', 0))
        amount = getattr(item, 'amount', float(qty or 0) * float(price or 0))
        
        grand_total += float(amount)
        
        item.safe_qty = qty
        item.computed_amount = amount 
        item.safe_code = getattr(item, 'item_code', None) or (item.item.item_code if hasattr(item, 'item') else 'N/A')
        item.safe_desc = getattr(item, 'description', None) or (item.item.description if hasattr(item, 'item') else '-')
        
    supplier_name = first_item.supplier.name if getattr(first_item, 'supplier', None) else 'Unknown Supplier'
    
    context = {
        'po_no': po_no,
        'supplier_name': supplier_name,
        'po_items': actual_items,
        'first_item': first_item,
        'grand_total': grand_total,
        'print_date': timezone.now(), # Oras ngayon kung kailan pinrint
    }
    
    return render(request, 'Inventory/inbound/shipment_print_doc.html', context)

# 2. VIEW PARA I-SAVE ANG ALLOCATION
def shipment_register_allocation(request, ship_id):
    if request.method == 'POST':
        main_shipment = ShipmentSchedule.objects.get(id=ship_id)
        related_items = ShipmentSchedule.objects.filter(invoice_no=main_shipment.invoice_no) if main_shipment.invoice_no else [main_shipment]

        for item in related_items:
            plan_qty = request.POST.get(f'plan_qty_{item.id}')
            remarks = request.POST.get(f'remarks_{item.id}')
            
            if plan_qty and int(plan_qty) > 0:
                item.status = 'Allocated'
                item.remarks = remarks
                item.save()

        messages.success(request, "Allocation successfully registered!")
        return redirect('shipment_inquiry')

def shipment_invoice_view(request, ship_id):
    main_shipment = ShipmentSchedule.objects.get(id=ship_id)
    related_items = ShipmentSchedule.objects.filter(invoice_no=main_shipment.invoice_no) if main_shipment.invoice_no else [main_shipment]
    
    context = {
        'shipment': main_shipment,
        'related_items': related_items,
        'doc_type': 'COMMERCIAL INVOICE'
    }
    return render(request, 'Inventory/inbound/shipment_print_doc.html', context)

def shipment_print_view(request, ship_id):
    main_shipment = ShipmentSchedule.objects.get(id=ship_id)
    related_items = ShipmentSchedule.objects.filter(invoice_no=main_shipment.invoice_no) if main_shipment.invoice_no else [main_shipment]
    
    context = {
        'shipment': main_shipment,
        'related_items': related_items,
        'doc_type': 'DELIVERY RECEIPT / PACKING SLIP' # Walang presyo dapat ito
    }
    return render(request, 'Inventory/inbound/shipment_print_doc.html', context)

def shipping_confirmation_view(request, po_no=None):
    # 1. SEARCH MODE
    if request.method == "POST" and 'search_po' in request.POST:
        search_po = request.POST.get('search_po', '').strip()
        if search_po:
            return redirect('shipping_confirmation', po_no=search_po)
        else:
            messages.warning(request, "Please enter a valid PO Number.")
            return redirect('shipping_confirmation')

    if not po_no:
        return render(request, 'Inventory/inbound/shipping_confirmation.html', {'po_no': None})

    # ==========================================
    # 2. CONFIRMATION MODE
    # ==========================================
    
    # Kunin ang PO Header
    po_qs = PurchaseOrder.objects.filter(po_no=po_no)
    
    if not po_qs.exists():
        messages.error(request, f"Error: Purchase Order '{po_no}' not found in the database.")
        return redirect('shipping_confirmation')
        
    first_item = po_qs.first()
    
    # 🚀 BULLETPROOF ITEM EXTRACTION (Kapareho ng Inquiry)
    actual_items = []
    if hasattr(first_item, 'items') and callable(getattr(first_item.items, 'all', None)):
        actual_items = list(first_item.items.all())
    else:
        actual_items = list(po_qs)

    # Defense: Baka na-confirm na ito dati
    if getattr(first_item, 'ordering_status', '') in ['Shipped', 'In Transit', 'Received']:
        messages.warning(request, f"PO {po_no} is already marked as {first_item.ordering_status}. No further confirmation needed.")
        return redirect('shipment_inquiry')

    # Kung i-su-submit na yung form
    if request.method == "POST" and 'confirm_shipment' in request.POST:
        courier = request.POST.get('courier', 'Unknown Courier').strip()
        tracking_no = request.POST.get('tracking_no', 'N/A').strip()
        eta = request.POST.get('eta', '')
        remarks = request.POST.get('remarks', '').strip()

        try:
            with transaction.atomic():
                po_qs.update(
                    ordering_status='In Transit',
                    transport=courier,
                    delivery_date=eta if eta else first_item.delivery_date,
                    remarks=f"TRK: {tracking_no} | {remarks}"
                )
                log_system_action(
                    user=request.user,
                    action='UPDATE',
                    module='Inbound Shipment',
                    description=f"Confirmed shipment for PO {po_no} via {courier}. Tracking: {tracking_no}",
                    request=request
                )
            messages.success(request, f"Success! Shipment for PO {po_no} has been confirmed and is now In Transit.")
            return redirect('shipment_inquiry')
        except Exception as e:
            messages.error(request, f"System Error while confirming shipment: {str(e)}")
            return redirect('shipping_confirmation', po_no=po_no)

    # 🚀 COMPUTATION & VARIABLE ATTACHMENT
    grand_total = 0.0
    for item in actual_items:
        # Kunin ang qty at price
        qty = getattr(item, 'quantity', getattr(item, 'qty', getattr(item, 'total_pcs', 0)))
        price = getattr(item, 'unit_price', getattr(item, 'price', 0))
        amount = getattr(item, 'amount', float(qty or 0) * float(price or 0))
        
        grand_total += float(amount)
        
        # I-attach natin sa object as "safe_" variables para madaling tawagin sa HTML
        item.safe_qty = qty
        item.computed_amount = amount 
        item.safe_code = getattr(item, 'item_code', None) or (item.item.item_code if hasattr(item, 'item') else 'N/A')
        item.safe_desc = getattr(item, 'description', None) or (item.item.description if hasattr(item, 'item') else '-')
        
    supplier_name = first_item.supplier.name if getattr(first_item, 'supplier', None) else 'Unknown Supplier'
    
    context = {
        'po_no': po_no,
        'supplier_name': supplier_name,
        'po_items': actual_items, # Ang TOTOONG items ang ipapasa natin
        'grand_total': grand_total,
        'first_item': first_item,
    }
    
    return render(request, 'Inventory/inbound/shipping_confirmation.html', context)

@login_required
@require_module_access('INV_REQUEST')
def new_request_view(request):
    if request.method == 'POST':
        department = request.POST.get('department')
        required_date = request.POST.get('required_date')
        purpose = request.POST.get('purpose')
        
        item_codes = request.POST.getlist('item_code[]')
        item_descs = request.POST.getlist('item_desc[]')
        request_qtys = request.POST.getlist('request_qty[]')
        item_remarks = request.POST.getlist('item_remarks[]')

        try:
            with transaction.atomic():
                new_req_no = f"REQ-{timezone.now().strftime('%Y%m%d-%H%M%S')}"

                new_req = DeliveryRequest.objects.create(
                    request_no=new_req_no,
                    request_date=timezone.now().date(),
                    delivery_date=required_date,
                    delivery_place="Main Warehouse",
                    receiving_place=department,
                    reason=purpose,
                    remarks=purpose,
                    status='Pending'
                )
                
                for i in range(len(item_codes)):
                    code = item_codes[i].strip()
                    if code: 
                        DeliveryRequestItem.objects.create(
                            request_header=new_req,
                            item_code=code,
                            description=item_descs[i] if i < len(item_descs) else '',
                            request_qty=int(request_qtys[i]),
                            delivered_qty=0,
                            remarks=item_remarks[i] if i < len(item_remarks) else ''
                        )

                # Send email notification
                try:
                    send_new_material_request_alert(new_req)
                except Exception as e:
                    print(f"Email Failed: {e}") # Wag i-crash ang system kung pumalpak ang email
                
                messages.success(request, f"Requisition Submitted! Request No: {new_req.request_no}")
                return redirect('my_requests')
                
        except Exception as e:
            messages.error(request, f"Failed to submit request: {str(e)}")
            return redirect('new_request')

    items_list = Item.objects.all().order_by('item_code')

    return render(request, 'Inventory/inventory_request/new_request.html', {'items': items_list})

# 3. MY REQUESTS VIEW
@login_required
@require_module_access('INV_REQUEST')
def my_requests_view(request):
    try:
        # Kukunin ang 50 latest requests at bibilangin kung ilang items ang nasa loob
        requests_list = DeliveryRequest.objects.annotate(
            item_count=Count('items') 
        ).order_by('-request_date', '-id')[:50] 
    except Exception as e:
        print(f"Error loading requests: {e}")
        requests_list = []
        
    context = {
        'requests': requests_list
    }
    return render(request, 'Inventory/inventory_request/my_requests.html', context)

# 2. ANG API PARA SA "VIEW DETAILS" MODAL
@login_required
def api_request_details(request, req_id):
    try:
        req = DeliveryRequest.objects.get(id=req_id)
        items_data = []
        
        for item in req.items.all():
            items_data.append({
                'item_code': item.item_code,
                'description': item.description,
                'request_qty': item.request_qty,
                'delivered_qty': item.delivered_qty, # Para makita nila kung ilan na ang na-pick
                'remarks': item.remarks
            })
            
        data = {
            'request_no': req.request_no,
            'department': req.receiving_place,
            'date': req.request_date.strftime('%Y-%m-%d'),
            'status': req.status,
            'purpose': req.reason,
            'items': items_data
        }
        return JsonResponse({'success': True, 'data': data})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# 5. RETURN SLIP VIEW
@login_required
@require_module_access('INV_REQUEST')
def return_slip_view(request):
    if request.method == 'POST':
        # (Nandito yung logic mo para sa Return Slip na ginawa natin kanina)
        ref_request_no = request.POST.get('ref_request_no', '').strip()
        department = request.POST.get('department')
        reason = request.POST.get('reason')
        item_codes = request.POST.getlist('ret_item_code[]')
        lot_nos = request.POST.getlist('ret_lot_no[]')
        return_qtys = request.POST.getlist('ret_qty[]')
        
        try:
            with transaction.atomic():
                for i in range(len(item_codes)):
                    code = item_codes[i].strip()
                    lot = lot_nos[i].strip()
                    qty = int(return_qtys[i])
                    
                    if code and qty > 0 and lot:
                        try:
                            tag = MaterialTag.objects.get(lot_no=lot)
                            old_qty = tag.total_pcs
                            tag.total_pcs += qty 
                            tag.save()
                            
                            StockLog.objects.create(
                                material_tag=tag,
                                action_type='REG', 
                                old_qty=old_qty,
                                new_qty=tag.total_pcs,
                                change_qty=qty,
                                notes=f"RETURNED from {department} (Ref: {ref_request_no}). Reason: {reason}",
                                user=request.user
                            )
                        except MaterialTag.DoesNotExist:
                            pass 
                messages.success(request, f"Return Slip submitted successfully for Ref: {ref_request_no}")
                return redirect('return_slip')
        except Exception as e:
            messages.error(request, f"Error processing return: {str(e)}")
            return redirect('return_slip')

    items_list = Item.objects.all().order_by('item_code')
    
    return render(request, 'Inventory/inventory_request/return_slip.html', {'items': items_list})


@login_required
@require_module_access('SYSTEM_ANALYTICS')
def analytics_view(request):
    try:
        settings = SystemSetting.objects.first()
        default_threshold = settings.low_stock_threshold if settings else 50
    except Exception:
        default_threshold = 50

    total_skus = Item.objects.count()
    try:
        pending_shipments = CustomerOrder.objects.filter(order_status='Pending').count()
    except Exception:
        pending_shipments = 0 
        
    total_pcs = MaterialTag.objects.aggregate(total=Sum('total_pcs'))['total'] or 0

    # 1. TOTAL INVENTORY VALUE (Pera)
    item_prices = {
        item['item_code']: item['unit_price'] 
        for item in Item.objects.values('item_code', 'unit_price')
    }

    active_tags = MaterialTag.objects.filter(total_pcs__gt=0)
    total_inventory_value = Decimal('0.00')
    for tag in active_tags:
        price = item_prices.get(tag.item_code, Decimal('0.00'))
        total_inventory_value += Decimal(str(tag.total_pcs)) * price

    # 🚀 2. STOCK HEALTH
    inventory_grouped = MaterialTag.objects.values('item_code', 'description').annotate(
        total_stock=Sum('total_pcs')
    )
    master_mins = {item['item_code']: item['min_stock'] for item in Item.objects.values('item_code', 'min_stock')}

    low_stock_items = []
    critical_count = 0
    healthy_count = 0

    for item in inventory_grouped:
        code = item['item_code']
        qty = item['total_stock'] or 0
        i_min = master_mins.get(code, 0)
        threshold_to_use = i_min if i_min > 0 else default_threshold

        if qty <= threshold_to_use:
            low_stock_items.append({
                'item_code': code,
                'description': item['description'],
                'total_stock': qty
            })
            critical_count += 1
        else:
            healthy_count += 1

    low_stock_items = sorted(low_stock_items, key=lambda k: k['total_stock'])[:5]

    # 🚀 3. INVENTORY FLOW (LAST 7 DAYS)
    today = timezone.now().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    
    flow_dates = [d.strftime('%b %d') for d in last_7_days]
    flow_in = []
    flow_out = []
    flow_net = []

    for d in last_7_days:
        day_in = StockLog.objects.filter(timestamp__date=d, action_type__in=['IN', 'REG']).aggregate(Sum('change_qty'))['change_qty__sum'] or 0
        day_out_raw = StockLog.objects.filter(timestamp__date=d, action_type='OUT').aggregate(Sum('change_qty'))['change_qty__sum'] or 0
        
        abs_out = abs(day_out_raw)
        
        flow_in.append(day_in)
        flow_out.append(abs_out)
        flow_net.append(day_in - abs_out)

    # 4. RECENT ACTIVITY FEED
    recent_logs = StockLog.objects.select_related('user', 'material_tag').order_by('-timestamp')[:6]

    # 🚀 5. PER WAREHOUSE UTILIZATION
    warehouses = LocationMaster.objects.values('warehouse').annotate(
        total_cap=Sum('capacity')
    ).exclude(warehouse__exact='').exclude(warehouse__isnull=True)

    used_per_wh = MaterialTag.objects.filter(location__isnull=False, total_pcs__gt=0).values('location__warehouse').annotate(
        used_qty=Sum('total_pcs')
    )
    used_dict = {item['location__warehouse']: item['used_qty'] for item in used_per_wh}

    wh_labels = []
    wh_util_data = []
    wh_used_data = [] 
    wh_free_data = []

    for wh in warehouses:
        wh_name = str(wh['warehouse']).strip()
        if not wh_name: continue
        
        t_cap = float(wh['total_cap'] or 1) 
        used = float(used_dict.get(wh_name, 0))
        free = max(t_cap - used, 0) # Computed free space

        pct = round((used / t_cap) * 100, 1)
        pct_capped = min(pct, 100) 

        wh_labels.append(wh_name.upper())
        wh_util_data.append(pct_capped)
        wh_used_data.append(used)
        wh_free_data.append(free)

    # 6. FAST MOVING ITEMS
    fast_movers = StockLog.objects.filter(action_type='OUT').values(
        'material_tag__item_code'
    ).annotate(
        total_out=Sum('change_qty')
    ).order_by('total_out')[:5]

    top_items = []
    for item in fast_movers:
        top_items.append({
            'item_code': item['material_tag__item_code'],
            'total_out': abs(item['total_out']) 
        })

    context = {
        'total_skus': total_skus,
        'pending_shipments': pending_shipments,
        'total_pcs': total_pcs,
        'total_inventory_value': total_inventory_value,
        'critical_count': critical_count,
        'low_stock_items': low_stock_items, 
        'recent_logs': recent_logs,
        'chart_health_data': json.dumps([healthy_count, critical_count]), 
        'flow_dates': json.dumps(flow_dates),
        'flow_in': json.dumps(flow_in),
        'flow_out': json.dumps(flow_out),
        'flow_net': json.dumps(flow_net),
        'wh_labels': json.dumps(wh_labels),
        'wh_util_data': json.dumps(wh_util_data),
        'wh_used_data': json.dumps(wh_used_data),
        'wh_free_data': json.dumps(wh_free_data),
        'top_items': top_items,
    }
    
    return render(request, 'Inventory/analytics_board.html', context)

@login_required
def receive_item_view(request):
    if request.method == 'POST':
        item_code = request.POST.get('item_code')
        loc_code = request.POST.get('location_code')
        qty = request.POST.get('qty')
        lot_no = request.POST.get('lot_no')

        # Logic: Hanapin ang Location, kung wala, error
        location, _ = LocationMaster.objects.get_or_create(location_code=loc_code)
        
        # Gawa ng bagong Material Tag (The Arrival)
        MaterialTag.objects.create(
            item_code=item_code,
            total_pcs=qty,
            lot_no=lot_no,
            location=location
        )

        log_system_action(
            user=request.user, 
            action='CREATE', 
            module='Item Receiving', 
            description=f"Received item {item_code} (Lot: {lot_no}) into Location: {loc_code}.", 
            request=request
        )

        return redirect('receive_item')

    return render(request, 'Inventory/receive_item.html', {
        'locations': LocationMaster.objects.all(),
        'items': ItemMaster.objects.all()
    })

@login_required
@require_module_access('SYS_CONFIG')
def location_master_view(request):
    # ==========================================
    # 1. POST: ADD / DELETE LOCATION
    # ==========================================
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'add':
            loc_code = request.POST.get('location_code', '').strip().upper()
            warehouse = request.POST.get('warehouse', '').strip().upper()
            zone = request.POST.get('zone', '').strip().upper()
            zone_type = request.POST.get('zone_type', '').strip().upper()
            capacity = int(request.POST.get('capacity', 0))
            desc = request.POST.get('description', '').strip()

            if LocationMaster.objects.filter(location_code=loc_code).exists():
                messages.error(request, f"Error: Location {loc_code} already exists!")
            else:
                LocationMaster.objects.create(
                    location_code=loc_code, 
                    warehouse=warehouse,
                    zone=zone, 
                    zone_type=zone_type,
                    capacity=capacity,
                    description=desc
                )
                log_system_action(request.user, 'CREATE', 'Location Master', f"Added {loc_code} in {warehouse}", request)
                messages.success(request, f"Success: Added {loc_code} to {warehouse} ({zone}).")

        # 🚀 BAGO: EDIT LOGIC
        elif action == 'edit':
            loc_id = request.POST.get('loc_id')
            loc_code = request.POST.get('location_code', '').strip().upper()
            warehouse = request.POST.get('warehouse', '').strip().upper()
            zone = request.POST.get('zone', '').strip().upper()
            zone_type = request.POST.get('zone_type', '').strip().upper()
            capacity = int(request.POST.get('capacity', 0))
            desc = request.POST.get('description', '').strip()

            try:
                loc = LocationMaster.objects.get(id=loc_id)
                # I-check kung papalitan niya ng code na nag-e-exist na sa Ibang Rack
                if LocationMaster.objects.filter(location_code=loc_code).exclude(id=loc_id).exists():
                    messages.error(request, f"Error: Location code {loc_code} is already used by another rack!")
                else:
                    loc.location_code = loc_code
                    loc.warehouse = warehouse
                    loc.zone = zone
                    loc.zone_type = zone_type
                    loc.capacity = capacity
                    loc.description = desc
                    loc.save()
                    
                    log_system_action(request.user, 'UPDATE', 'Location Master', f"Edited details of {loc_code}", request)
                    messages.success(request, f"Success: Updated location {loc_code}.")
            except Exception as e:
                messages.error(request, f"Error updating location: {str(e)}")

        elif action == 'delete':
            loc_id = request.POST.get('loc_id')
            try:
                loc = LocationMaster.objects.get(id=loc_id)
                loc_code = loc.location_code
                loc.delete()
                messages.success(request, f"Successfully deleted location {loc_code}.")
            except Exception as e:
                messages.error(request, f"Error deleting location: {str(e)}")

        return redirect('location_master')

    # ==========================================
    # 2. GET: SEARCH, COMPUTE & DISPLAY
    # ==========================================
    search_query = request.GET.get('q', '')
    locations_qs = LocationMaster.objects.all().order_by('warehouse', 'zone', 'location_code')

    if search_query:
        locations_qs = locations_qs.filter(
            Q(zone__icontains=search_query) | 
            Q(location_code__icontains=search_query) |
            Q(warehouse__icontains=search_query)
        )

    # 🚀 COMPUTATION NG CURRENT ITEMS AT UTILIZATION
    locations_data = []
    for loc in locations_qs:
        # Kunin lahat ng laman ng rack na 'to mula sa MaterialTag
        current_items = MaterialTag.objects.filter(location=loc, total_pcs__gt=0).aggregate(total=Sum('total_pcs'))['total'] or 0
        
        # Computation ng porsyento (%)
        cap = loc.capacity if loc.capacity > 0 else 1 # Iwas Divide-by-Zero error
        utilization = (current_items / cap) * 100 if loc.capacity > 0 else 0
        
        # Determine ang Status
        if loc.capacity == 0:
            status = "NO CAPACITY SET"
        elif utilization >= 100:
            status = "FULL"
        elif utilization >= 80:
            status = "ALMOST FULL"
        elif current_items > 0:
            status = "AVAILABLE"
        else:
            status = "EMPTY"

        locations_data.append({
            'id': loc.id,
            'location_code': loc.location_code,
            'warehouse': loc.warehouse,
            'zone': loc.zone,
            'zone_type': loc.zone_type,
            'capacity': loc.capacity,
            'description': loc.description,
            'current_items': current_items,
            'utilization': utilization,
            'status': status,
        })

    return render(request, 'Inventory/master/location_master.html', {
        'locations': locations_data,
        'search_query': search_query
    })

# 2. ANG PRINT BARCODE VIEW
def print_tag_view(request, tag_id):
    # Kukunin yung mismong sticker data na kaka-save lang
    tag = get_object_or_404(MaterialTag, id=tag_id)
    return render(request, 'Inventory/print_tag.html', {'tag': tag})

# 3. I-UPDATE ANG RECEIVING VIEW MO KANINA
@login_required
@require_module_access('SYS_CONFIG')
def receive_item_scan_view(request):
    if request.method == 'POST':
        item_code = request.POST.get('item_code')
        loc_code = request.POST.get('location_code')
        qty = request.POST.get('qty')
        lot_no = request.POST.get('lot_no')

        location, _ = LocationMaster.objects.get_or_create(location_code=loc_code)
        
        # Pagka-save sa Database...
        new_tag = MaterialTag.objects.create(
            item_code=item_code,
            description="Item Received via Scanner", # Pinalitan ko para madali mong ma-identify
            total_pcs=qty,
            lot_no=lot_no,
            location=location
        )

        log_system_action(
            user=request.user, 
            action='CREATE', 
            module='Scanner Operations', 
            description=f"Scanned and received item {item_code} (Lot: {lot_no}) into {loc_code}.", 
            request=request
        )

        # Redirect papunta sa Print Page gamit ang ID ng bagong tag
        return redirect('print_tag', tag_id=new_tag.id)

    # Pansinin: Pinalitan ko rin ang pangalan ng HTML file na tatawagin niya
    return render(request, 'Inventory/receive_item_scan.html', {
        'locations': LocationMaster.objects.all(),
        'items': ItemMaster.objects.all()
    })

@login_required(login_url='login')
def stock_out_item(request, item_id):
    # Kukunin natin yung item sa database gamit ang ID
    item = get_object_or_404(Item, id=item_id) 

    if request.method == 'POST':
        # Kunin ang tinype na quantity sa form
        deduct_qty = int(request.POST.get('quantity', 0))

        if deduct_qty > 0 and deduct_qty <= item.current_stock:
            # 1. Bawasan ang stock sa database
            item.current_stock -= deduct_qty
            item.save()

            log_system_action(
                user=request.user, 
                action='UPDATE', 
                module='Inventory Adjustment', 
                description=f"Dispensed {deduct_qty} pcs of {item.item_name}. Remaining: {item.current_stock}", 
                request=request
            )

            # ==========================================
            # 2. TAWAGIN ANG EMAIL TRIGGER NATIN!
            # ==========================================
            check_and_alert_low_stock(item)

            messages.success(request, f"Success! Dispensed {deduct_qty} units of {item.item_name}. Remaining stock: {item.current_stock}")
            
            # I-redirect pabalik sa listahan ng items (palitan ng tamang url name mo kung iba)
            # return redirect('item_list') 
            return redirect('/admin/') # Pansamantala, ibalik muna natin sa admin page mo
        else:
            messages.error(request, "Error: Invalid quantity. You cannot deduct more than the current stock.")

    # Kung GET request, ipapakita yung form
    return render(request, 'Inventory/stock_out.html', {'item': item})

@login_required
@require_module_access('SYS_CONFIG')
def system_audit_logs_view(request):
    log_list = SystemAuditLog.objects.all().select_related('user').order_by('-timestamp')
    paginator = Paginator(log_list, 15) 
    page_number = request.GET.get('page')
    logs = paginator.get_page(page_number)
    
    return render(request, 'Inventory/master/System_Audit_Logs.html', {'logs': logs})

@login_required
def all_notifications_view(request):
    """ Ipapakita lahat ng notifications ng user, luma man o bago """
    # Kukunin lahat ng notifs ng naka-login na user
    notifs = SystemNotification.objects.filter(user=request.user).order_by('-created_at')
    
    # Optional: Paginator kung sakaling umabot na sa libo yung alerts
    from django.core.paginator import Paginator
    paginator = Paginator(notifs, 50) # 50 alerts per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'Inventory/notifications_list.html', {'notifs': page_obj})

@login_required
def mark_all_read_view(request):
    """ Isang pindot para gawing 'Read' lahat ng unread notifications """
    SystemNotification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    
    messages.success(request, "All notifications marked as read.")
    # Ibabalik ka niya kung saang page ka man nanggaling nung pinindot mo 'to
    return redirect(request.META.get('HTTP_REFERER', 'dashboard'))

@login_required
@require_module_access('ASSET_WIP')
def assembly_dashboard_view(request):
    # ==========================================
    # 1. POST: CREATE NEW MACHINE / ASSET
    # ==========================================
    if request.method == 'POST':
        machine_code = request.POST.get('machine_code').strip().upper()
        name = request.POST.get('name').strip()
        description = request.POST.get('description').strip()

        if MachineAsset.objects.filter(machine_code=machine_code).exists():
            messages.error(request, f"Error: Machine Code '{machine_code}' already exists!")
        else:
            MachineAsset.objects.create(
                machine_code=machine_code,
                name=name,
                description=description,
                status='Building' 
            )
            messages.success(request, f"Success: Asset '{machine_code}' created. Ready for assembly.")
        
        return redirect('assembly_dashboard')

    # ==========================================
    # 2. GET: LOAD DASHBOARD, KPIs & FILTERS
    # ==========================================
    machines_query = MachineAsset.objects.all().order_by('-created_at')

    # Compute KPI Stats (Compute bago mag-filter para accurate ang totals)
    total_assets = machines_query.count()
    building_count = machines_query.filter(status='Building').count()
    available_count = machines_query.filter(status='Available').count()
    partial_count = machines_query.filter(status='Partial').count()

    # Apply Search & Filters
    search_query = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')

    if search_query:
        machines_query = machines_query.filter(
            Q(machine_code__icontains=search_query) | 
            Q(name__icontains=search_query)
        )
    if status_filter:
        machines_query = machines_query.filter(status=status_filter)

    # Pagination (20 machines per page)
    paginator = Paginator(machines_query, 20)
    page_number = request.GET.get('page')
    machines_page = paginator.get_page(page_number)

    # Preserve filters para sa Next/Prev page
    query_dict = request.GET.copy()
    if 'page' in query_dict:
        del query_dict['page']
    filter_params = query_dict.urlencode()

    context = {
        'machines': machines_page,
        'total_assets': total_assets,
        'building_count': building_count,
        'available_count': available_count,
        'partial_count': partial_count,
        'search_query': search_query,
        'status_filter': status_filter,
        'filter_params': filter_params,
    }
    return render(request, 'Inventory/assembly/assembly_dashboard.html', context)

@login_required
@require_module_access('ASSET_WIP')
def machine_detail_view(request, machine_id):
    machine = get_object_or_404(MachineAsset, id=machine_id)

    # ==========================================
    # CORE PRINCIPLE: DERIVE STATE FROM EVENTS
    # ==========================================
    # Hindi tayo nagse-save ng "current_qty" sa machine. Kino-compute natin siya!
    # Formula: (Sum ng Assemble) - (Sum ng Dismantle) per Material Tag
    
    installed_parts = MachineComponent.objects.filter(machine=machine).values(
        'material_tag__id',
        'material_tag__item_code',
        'material_tag__description',
        'material_tag__lot_no'
    ).annotate(
        net_qty=Sum(
            Case(
                When(action='Assemble', then=F('qty')),
                When(action='Dismantle', then=-F('qty')),
                default=0,
                output_field=DecimalField()
            )
        )
    ).filter(net_qty__gt=0) # Ipakita lang yung mga may natitira pang nakakabit

    # Kunin yung buong Event Ledger / History para sa Audit Trail
    ledger_logs = machine.components.all().order_by('-timestamp')

    print_log_id = request.GET.get('print_log')
    print_log = None
    if print_log_id:
        print_log = MachineComponent.objects.filter(id=print_log_id).first()

    context = {
        'machine': machine,
        'installed_parts': installed_parts,
        'ledger_logs': ledger_logs,
        'print_log': print_log, # 🚀 IDAGDAG ITO SA CONTEXT
    }
    return render(request, 'Inventory/assembly/machine_detail.html', context)

@login_required
@require_module_access('ASSET_WIP')
def api_assembly_action(request):
    if request.method == 'POST':
        machine_id = request.POST.get('machine_id')
        tag_id_raw = request.POST.get('tag_id').strip().upper()
        action = request.POST.get('action')
        qty = Decimal(request.POST.get('qty', 1))
        custom_remarks = request.POST.get('remarks', '').strip()

        try:
            tag_id = int(tag_id_raw.replace('TAG-', ''))
        except ValueError:
            messages.error(request, "Invalid TAG format. Please use 'TAG-00001'.")
            return redirect('machine_detail', machine_id=machine_id)

        try:
            with transaction.atomic():
                machine = MachineAsset.objects.get(id=machine_id)
                tag = MaterialTag.objects.get(id=tag_id)

                if action == 'Assemble':
                    if tag.total_pcs < qty:
                        messages.error(request, f"Insufficient stock! Tag {tag_id_raw} only has {tag.total_pcs} pcs.")
                        return redirect('machine_detail', machine_id=machine_id)
                    
                    tag.total_pcs -= qty
                    tag.save()
                    
                    StockLog.objects.create(
                        material_tag=tag, action_type='OUT', old_qty=tag.total_pcs + qty,
                        new_qty=tag.total_pcs, change_qty=qty, user=request.user,
                        notes=f"Assembled into Machine: {machine.machine_code}"
                    )

                elif action == 'Dismantle':
                    tag.total_pcs += qty
                    tag.save()
                    
                    StockLog.objects.create(
                        material_tag=tag, action_type='IN', old_qty=tag.total_pcs - qty,
                        new_qty=tag.total_pcs, change_qty=qty, user=request.user,
                        notes=f"Dismantled from Machine: {machine.machine_code}"
                    )

                final_remarks = custom_remarks if custom_remarks else f"System generated {action.lower()} log."

                # CREATE LEDGER LOG
                new_log = MachineComponent.objects.create(
                    machine=machine,
                    material_tag=tag,
                    action=action,
                    qty=qty,
                    performed_by=request.user,
                    remarks=final_remarks
                )

                if action == 'Dismantle':
                    machine.status = 'Partial'
                elif action == 'Assemble':
                    machine.status = 'Building'

                machine.save()
                messages.success(request, f"Successfully {action.lower()}d {qty}x of {tag.item_code}.")

                # 🚀 KUNG ASSEMBLE, IPAPASA NATIN YUNG LOG ID PARA MA-PRINT ANG STICKER
                return redirect(f"{reverse('machine_detail', args=[machine_id])}?print_log={new_log.id}")

        except Exception as e:
            messages.error(request, f"System Error: {str(e)}")

        return redirect('machine_detail', machine_id=machine_id)

@login_required
def api_assembly_complete(request):
    """ View para tapusin ang assembly at gawing 'Available' ang makina """
    if request.method == 'POST':
        machine_id = request.POST.get('machine_id')
        machine = get_object_or_404(MachineAsset, id=machine_id)
        
        # Papalitan ang status niya to Available
        machine.status = 'Available'
        machine.save()
        
        # 🚀 TAWAGIN ANG EMAIL TRIGGER DITO
        try:
            send_assembly_completed_alert(machine)
        except Exception as e:
            print(f"Assembly Email Failed: {e}")
        
        messages.success(request, f"Asset {machine.machine_code} marked as Complete and Available!")
        
        # Babalik sa workspace
        return redirect('machine_detail', machine_id=machine_id)

# 2. IDAGDAG ITO SA PINAKABABA NG views.py
@login_required
def print_assembly_label(request, log_id):
    """ View na maglalabas ng format para sa Thermal Barcode Printer """
    log = get_object_or_404(MachineComponent, id=log_id)
    return render(request, 'Inventory/assembly/assembly_print_label.html', {'log': log})

@login_required
@require_module_access('ASSET_WIP')
def machine_create_view(request):
    """ View na taga-salos ng Form Submission para sa bagong Makina """
    if request.method == 'POST':
        machine_code = request.POST.get('machine_code').strip().upper()
        name = request.POST.get('name').strip()
        description = request.POST.get('description').strip()

        # Check kung may kapangalan nang Machine Code (bawal ang duplicate)
        if MachineAsset.objects.filter(machine_code=machine_code).exists():
            messages.error(request, f"Error: Machine Code '{machine_code}' already exists!")
        else:
            MachineAsset.objects.create(
                machine_code=machine_code,
                name=name,
                description=description,
                status='Building' # Default status
            )
            messages.success(request, f"Success: Asset '{machine_code}' created. Ready for assembly.")
        
    return redirect('assembly_dashboard')

    


# Email views

def check_and_alert_low_stock(tag):
    try:
        system_settings = SystemSetting.objects.first()
        
        if not system_settings:
            print("Error: No System Settings found in database.")
            return

        threshold = system_settings.low_stock_threshold
        
        if tag.total_pcs <= threshold:
            notify_admins(
                title="⚠️ Low Stock Alert",
                message=f"Critical! Lot {tag.lot_no} ({tag.item_code}) is down to {tag.total_pcs} pcs.",
                link="/inventory/inquiry/" 
            )
            
            route = EmailRoute.objects.filter(event_name='LOW_STOCK', is_active=True).first()
            
            if route:
                target_emails = route.get_email_list()
                
                if target_emails:
                    subject = f"URGENT: Low Stock Alert - Lot No: {tag.lot_no}"
                    
                    # 🚀 ANG MAGIC: I-pack ang data na ipapasa sa HTML
                    context = {
                        'item_code': tag.item_code,
                        'description': tag.description,
                        'lot_no': tag.lot_no,
                        'current_stock': tag.total_pcs,
                        'threshold': threshold
                    }
                    
                    # 🚀 I-render ang HTML design mo
                    html_message = render_to_string('Inventory/emails/low_stock_email.html', context)
                    
                    # 🚀 Gumawa ng plain text fallback (Para sa mga lumang email clients)
                    plain_message = strip_tags(html_message)
                    
                    # I-send ang email gamit ang html_message parameter
                    send_mail(
                        subject, 
                        plain_message, # Fallback text
                        django_settings.DEFAULT_FROM_EMAIL, 
                        target_emails, 
                        html_message=html_message, # Ang magandang design natin!
                        fail_silently=False
                    )
                    print(f"Low stock HTML email sent successfully for {tag.lot_no}!")
            else:
                print("Notice: No active email route setup for LOW_STOCK event.")

    except Exception as e:
        print(f"Email sending failed: {str(e)}")

def alert_new_po_created(po):
    try:
        route = EmailRoute.objects.get(event_name='PO_APPROVAL', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            supplier_name = po.supplier.name if hasattr(po, 'supplier') and po.supplier else "N/A"
            subject = f"NEW P.O. GENERATED: {po.po_no}"
            
            # 🚀 I-pack ang data papunta sa HTML
            context = {
                'po_no': po.po_no,
                'supplier_name': supplier_name,
                'order_date': po.order_date,
            }
            
            # 🚀 I-render ang template
            html_message = render_to_string('Inventory/emails/po_alert_email.html', context)
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject, 
                plain_message, 
                django_settings.DEFAULT_FROM_EMAIL, 
                target_emails, 
                html_message=html_message, # 🚀 Ipasa ang design!
                fail_silently=False
            )
            print(f"Success: New PO HTML email alert sent for {po.po_no}")
            
    except EmailRoute.DoesNotExist:
        print("Notice: Walang naka-setup na email sa PO_APPROVAL route.")
    except Exception as e:
        print(f"Error sending PO email: {str(e)}")

@login_required
@require_module_access('SYS_CONFIG')
def email_master_view(request):
    search_query = request.GET.get('q', '').strip()
    
    # Kunin lahat ng naka-setup na rules sa database
    routes = EmailRoute.objects.all().order_by('event_name')

    # 🚀 BAGO: Search Logic (Hahanapin sa Event Name o sa mismong naka-save na Emails)
    if search_query:
        routes = routes.filter(
            Q(event_name__icontains=search_query) |
            Q(target_emails__icontains=search_query)
        )

    context = {
        'routes': routes,
        'search_query': search_query
    }
    
    return render(request, 'Inventory/master/email_master.html', context)

@login_required
def update_email_route(request):
    if request.method == "POST":
        route_id = request.POST.get('route_id')
        new_emails = request.POST.get('target_emails')
        # Checkbox logic: kung naka-check, 'on' ang value nito
        is_active = request.POST.get('is_active') == 'on' 

        try:
            route = EmailRoute.objects.get(id=route_id)
            route.target_emails = new_emails
            route.is_active = is_active
            route.save()

            status_text = "Enabled" if is_active else "Disabled"
            log_system_action(
                user=request.user, 
                action='UPDATE', 
                module='System Settings', 
                description=f"Updated Email Route for '{route.event_name}': {status_text} | Emails: {new_emails}", 
                request=request
            )

            messages.success(request, f"Success! Notification settings for '{route.get_event_name_display()}' updated.")
        except Exception as e:
            messages.error(request, f"Error updating email route: {str(e)}")
            
    return redirect('email_master')

def scan_and_alert_expiring_items():
    today = timezone.now().date()
    warning_limit = today + timedelta(days=30)

    expiring_tags = MaterialTag.objects.filter(
        total_pcs__gt=0,
        expiration_date__lte=warning_limit,
        expiration_date__gte=today
    ).order_by('expiration_date')

    if not expiring_tags.exists():
        return 0 

    try:
        route = EmailRoute.objects.get(event_name='EXPIRING_STOCKS', is_active=True)
        target_emails = route.get_email_list()

        if target_emails:
            # 🚀 I-pack ang data sa isang list para ma-loop ng HTML
            items_data = []
            for tag in expiring_tags:
                days_left = (tag.expiration_date - today).days
                items_data.append({
                    'lot_no': tag.lot_no,
                    'item_code': tag.item_code,
                    'qty': tag.total_pcs,
                    'days_left': days_left
                })

            subject = f"URGENT: {expiring_tags.count()} Materials Expiring Soon"
            context = {'items': items_data, 'total_count': expiring_tags.count()}
            
            html_message = render_to_string('Inventory/emails/expiring_stocks_email.html', context)
            plain_message = strip_tags(html_message)

            send_mail(subject, plain_message, django_settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
            return expiring_tags.count()
            
    except Exception as e:
        print(f"Error sending Expiry Alert: {str(e)}")
    return 0

# ==============================================================
# ANG BUTTON TRIGGER (Para ma-test natin nang manual)
# ==============================================================
@login_required
def trigger_expiry_scan(request):
    """ View na tatawagin kapag pinindot ang button sa system """
    if request.method == 'POST':
        try:
            # 🚀 THE MAGIC: Pinapatakbo nito yung scan_expiry.py na ginawa natin kanina!
            # Sakop na nito ang Expiry, Late Delivery, Low Stock, at All Goods Email.
            call_command('scan_expiry')
            
            # Magpapalabas ng Toast Notification sa Top-Right ng screen mo
            messages.success(request, "Automated System Scan triggered successfully! Check your email for the results.")
            
        except Exception as e:
            messages.error(request, f"Engine Error: Failed to run scan. Details: {str(e)}")
            
    # I-redirect pabalik sa Dashboard mo
    return redirect('analytics_board')

@receiver(user_login_failed)
def track_failed_login_attempts(sender, credentials, request, **kwargs):
    username = credentials.get('username', 'unknown')
    ip_address = request.META.get('REMOTE_ADDR')
    
    # Gagawa tayo ng unique key para sa user at IP na ito
    cache_key = f"failed_login_{username}_{ip_address}"
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, 300) # I-store ng 5 minutes

    print(f"DEBUG: Failed login attempt #{attempts} for user: {username} from IP: {ip_address}")

    # Kung umabot na sa 5 attempts (o 3, depende sa gusto mo)
    if attempts == 5:
        send_security_alert_email(username, ip_address, attempts)

def send_security_alert_email(username, ip, count):
    try:
        route = EmailRoute.objects.get(event_name='SECURITY_ALERT', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"⚠️ SECURITY WARNING: Multiple Failed Logins for [{username}]"
            context = {'username': username, 'ip': ip, 'count': count}
            
            html_message = render_to_string('Inventory/emails/security_alert_email.html', context)
            plain_message = strip_tags(html_message)
            
            send_mail(subject, plain_message, django_settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
            print(f"Security Alert Email sent to {target_emails}")
            
    except Exception as e:
        print(f"Notice: Error with SECURITY_ALERT. {str(e)}")

@receiver(pre_save, sender=MaterialTag)
def alert_on_qc_failure(sender, instance, **kwargs):
    if not instance.pk:
        return

    try:
        old_instance = MaterialTag.objects.get(pk=instance.pk)
        
        if old_instance.inspection_status != 'Failed' and instance.inspection_status == 'Failed':

            notify_admins(
                title="🚨 QC Rejected",
                message=f"Lot {instance.lot_no} failed quality inspection!",
                link=f"/processing/stock-io/{instance.id}/"
            )
            
            route = EmailRoute.objects.get(event_name='QC_FAILED', is_active=True)
            target_emails = route.get_email_list()
            
            if target_emails:
                subject = f"🚨 URGENT QC ALERT: Material Rejected - Lot: {instance.lot_no}"
                
                # 🚀 I-pack ang data papunta sa HTML
                context = {
                    'item_code': instance.item_code,
                    'description': instance.description,
                    'lot_no': instance.lot_no,
                    'qty': instance.total_pcs,
                    'uom': instance.packing_type,
                    'remarks': instance.remarks or 'No remarks provided by inspector.'
                }
                
                # 🚀 I-render ang template
                html_message = render_to_string('Inventory/emails/qc_failed_email.html', context)
                plain_message = strip_tags(html_message)
                
                send_mail(
                    subject, 
                    plain_message, 
                    django_settings.DEFAULT_FROM_EMAIL, 
                    target_emails, 
                    html_message=html_message, # 🚀 Ipasa ang design!
                    fail_silently=False
                )
                print(f"QC Failure HTML Email Alert sent for Lot: {instance.lot_no}")
                
    except MaterialTag.DoesNotExist:
        pass
    except EmailRoute.DoesNotExist:
        print("Notice: No email route setup for QC_FAILED.")
    except Exception as e:
        print(f"Error sending QC Failure Alert: {str(e)}")

def scan_and_alert_late_deliveries():
    today = timezone.now().date()
    overdue_pos = PurchaseOrder.objects.filter(
        ordering_status__in=['Approved', 'Pending Approval'], 
        delivery_date__lt=today
    ).order_by('delivery_date')

    if not overdue_pos.exists():
        return 0

    try:
        route = EmailRoute.objects.get(event_name='LATE_DELIVERY', is_active=True)
        target_emails = route.get_email_list()

        if target_emails:
            po_data = []
            for po in overdue_pos:
                days_overdue = (today - po.delivery_date).days
                supplier = po.supplier.name if hasattr(po, 'supplier') and po.supplier else "N/A"
                po_data.append({
                    'po_no': po.po_no,
                    'supplier': supplier,
                    'days_late': days_overdue
                })

            subject = f"⚠️ LOGISTICS ALERT: {overdue_pos.count()} Overdue Purchase Orders"
            context = {'pos': po_data, 'total_count': overdue_pos.count()}
            
            html_message = render_to_string('Inventory/emails/late_delivery_email.html', context)
            plain_message = strip_tags(html_message)

            send_mail(subject, plain_message, django_settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
            return overdue_pos.count()
            
    except Exception as e:
        print(f"Error sending Late Delivery Alert: {str(e)}")
    return 0

def mark_order_shipped_view(request, order_id):
    if request.method == 'POST':
        # 1. Hanapin ang order sa database
        order = get_object_or_404(CustomerOrder, id=order_id)
        
        # 2. Kunin ang Courier galing sa input form ng staff
        courier = request.POST.get('courier_name', 'Standard Delivery')
        tracking = request.POST.get('tracking_no', '')

        # 3. I-update ang status sa Database
        order.status = 'Shipped'
        order.courier = courier
        order.tracking_number = tracking
        order.save() # Na-save na sa system!

        log_system_action(
            user=request.user, 
            action='UPDATE', 
            module='Customer Order', 
            description=f"Marked Order {order.order_no} as Shipped via {courier} (TRK: {tracking}).", 
            request=request
        )

        # 4. 🚀 THE TRIGGER: Ipadala ang Email sa Customer!
        email_sent = send_shipping_notification(
            order_no=order.order_no,
            customer_email=order.customer.email, # Siguraduhing may email field ang customer model mo
            courier_name=courier,
            tracking_number=tracking
        )

        # 5. Magbigay ng feedback sa staff
        if email_sent:
            messages.success(request, f"Order {order.order_no} tagged as Shipped! Customer has been notified via email.")
        else:
            messages.warning(request, f"Order {order.order_no} tagged as Shipped, BUT system failed to email the customer (No email found/SMTP error).")

        return redirect('some_order_list_view')

def alert_po_status_update(po, manager_user):
    # Siguraduhin na may email yung taong gumawa ng PO
    recipient_email = po.created_by.email if po.created_by and po.created_by.email else None
    
    if not recipient_email:
        print(f"Notice: Walang email address si {po.created_by.username}. Skipping status update email.")
        return

    try:
        subject = f"P.O. UPDATE: {po.po_no} is {po.ordering_status}"
        
        context = {
            'status': po.ordering_status,
            'po_no': po.po_no,
            'supplier': po.supplier.name if po.supplier else 'N/A',
            'manager': manager_user.username if manager_user else 'System Admin'
        }

        html_message = render_to_string('Inventory/emails/po_status_update_email.html', context)
        plain_message = strip_tags(html_message)

        send_mail(
            subject, 
            plain_message, 
            django_settings.DEFAULT_FROM_EMAIL, 
            [recipient_email], # Ise-send sa mismong Purchasing Staff
            html_message=html_message, 
            fail_silently=False
        )
        print(f"PO Status update email sent to {recipient_email}")
            
    except Exception as e:
        print(f"Error sending PO status email: {str(e)}")

def scan_and_alert_low_stock():
    print("\n--- RUNNING LOW STOCK DEBUG (WMS STANDARD) ---") 
    
    # 1. Kunin ang Default Threshold sa System Settings
    sys_settings = SystemSetting.objects.first()
    default_threshold = sys_settings.low_stock_threshold if sys_settings else 50
    
    # 2. Kunin lahat ng GLOBAL stock totals sa ISANG QUERY LANG (No lag!)
    tag_stocks = MaterialTag.objects.values('item_code').annotate(
        total_stock=Sum('total_pcs')
    )
    
    # I-convert sa dictionary para mabilis hanapin: {'ITEM-A': 100, 'ITEM-B': 20}
    stock_dict = {
        str(tag['item_code']).strip().upper(): (tag['total_stock'] or 0) 
        for tag in tag_stocks if tag['item_code']
    }

    all_items = Item.objects.all()
    low_stock_items = []
    
    for item in all_items:
        safe_item_code = str(item.item_code).strip().upper()
        
        # 3. Kunin ang total stock from dictionary, kung wala sa warehouse = 0
        total_stock = stock_dict.get(safe_item_code, 0)
        
        # 4. WMS LOGIC: Gamitin ang min_stock ng item. Kung wala, use system default.
        item_min_stock = getattr(item, 'min_stock', 0)
        threshold_to_use = item_min_stock if item_min_stock > 0 else default_threshold
        
        print(f"Checking {safe_item_code}: Found {total_stock} PCS (Min: {threshold_to_use})")
        
        # 5. I-check kung ang GLOBAL TOTAL ay mas mababa o pantay sa threshold
        if total_stock <= threshold_to_use:
            low_stock_items.append({
                'item_code': safe_item_code,
                'description': item.description,
                'current_stock': total_stock,
                'threshold': threshold_to_use
            })
            
    print("-------------------------------\n")
            
    # 6. Mag-send ng Email kung may nakitang Low Stock
    if low_stock_items:
        try:
            route = EmailRoute.objects.get(event_name='LOW_STOCK', is_active=True)
            target_emails = route.get_email_list()
            
            if target_emails:
                context = {
                    'items': low_stock_items,
                    'total_count': len(low_stock_items)
                }
                html_msg = render_to_string('Inventory/emails/low_stock_email.html', context)
                
                send_mail(
                    subject=f"⚠️ WMS ALERT: {len(low_stock_items)} Low Stock Items Detected",
                    message="Low stock items detected. Please check system.",
                    from_email=settings.DEFAULT_FROM_EMAIL, 
                    recipient_list=target_emails,
                    html_message=html_msg,
                    fail_silently=False
                )
                print(f"✅ Alert Email sent to {target_emails}")
        except Exception as e:
            print(f"❌ Error sending Low Stock email: {str(e)}")
            
    return len(low_stock_items)

@login_required
def test_all_email_templates_view(request):
    try:
        route = EmailRoute.objects.get(event_name='TEST_ALERT', is_active=True)
        target_emails = route.get_email_list()

        if not target_emails:
            messages.warning(request, "Test Failed: Walang nakalagay na email sa TEST_ALERT route mo.")
            return redirect('email_master')

        # Gagawa tayo ng helper function para hindi paulit-ulit ang code sa pag-send
        def send_test(subject, template_name, context):
            html_msg = render_to_string(f'Inventory/emails/{template_name}', context)
            send_mail(
                subject=f"🧪 TEST: {subject}",
                message=strip_tags(html_msg), 
                from_email=django_settings.DEFAULT_FROM_EMAIL,
                recipient_list=target_emails,
                html_message=html_msg,
                fail_silently=False
            )

        # 1. LOW STOCK ALERT
        send_test("Low Stock Alert", "low_stock_email.html", {
            'item_code': 'BOLT-M8-TEST', 'description': 'Stainless Steel Bolt',
            'lot_no': 'LOT-TEST-001', 'current_stock': 5, 'threshold': 50
        })

        # 2. P.O. GENERATED
        send_test("New P.O. Generated", "po_alert_email.html", {
            'po_no': 'PO-2026-TEST-999', 'supplier_name': 'Global Metals Inc.', 'order_date': 'March 24, 2026'
        })

        # 3. QC REJECTED
        send_test("QC Inspection Failed", "qc_failed_email.html", {
            'item_code': 'SENSOR-X1', 'description': 'Proximity Sensor',
            'lot_no': 'LOT-QC-404', 'qty': 150, 'uom': 'PCS', 'remarks': 'Visible damages on packaging. Failed calibration.'
        })

        # 4. EXPIRING MATERIALS
        send_test("Expiring Materials (30 Days)", "expiring_stocks_email.html", {
            'items': [
                {'lot_no': 'LOT-EXP-01', 'item_code': 'CHEMICAL-A', 'qty': 50, 'days_left': 12},
                {'lot_no': 'LOT-EXP-02', 'item_code': 'PAINT-RED', 'qty': 20, 'days_left': 5}
            ], 'total_count': 2
        })

        # 5. LATE DELIVERIES
        send_test("Overdue Deliveries", "late_delivery_email.html", {
            'pos': [
                {'po_no': 'PO-LATE-101', 'supplier': 'Fast Track Logistics', 'days_late': 7},
                {'po_no': 'PO-LATE-102', 'supplier': 'Tech Parts Corp', 'days_late': 3}
            ], 'total_count': 2
        })

        # 6. SECURITY ALERT (Failed Logins)
        send_test("Security Alert (Multiple Failed Logins)", "security_alert_email.html", {
            'username': 'admin_test_acc', 'ip': '192.168.1.104', 'count': 5
        })

        # 7. NEW USER REGISTRATION
        send_test("New User Registered", "user_welcome_email.html", {  # 🚀 Pinalitan ng tamang filename!
            'username': 'juan_delacruz', 'role': 'Warehouse Staff', 'company_name': 'Receiving Department'
        })

        # 8. NEW DELIVERY REQUEST
        send_test("New Movement Slip Requested", "new_delivery_request_email.html", {
            'req_no': 'REQ-2026-0001', 
            'destination': 'Production Line 1', 
            'requestor': 'Engr. Santos',
            'item_count': 5,
            'remarks': 'Urgent materials for project alpha.'
        })

        # 9. PO STATUS UPDATE (Approved Sample)
        send_test("PO Status Approved", "po_status_update_email.html", {
            'status': 'Approved', 
            'po_no': 'PO-2026-0001', 
            'supplier': 'Steel Supply Co.',
            'manager': 'Manager.Santos'
        })

        # 10. PO STATUS UPDATE (Rejected Sample)
        send_test("PO Status Rejected", "po_status_update_email.html", {
            'status': 'Rejected', 
            'po_no': 'PO-2026-0002', 
            'supplier': 'Plastic Moldings Inc.',
            'manager': 'Manager.Santos'
        })

        # 🚀 11. NEW MATERIAL REQUEST (Gumawa tayo ng dummy class para hindi mag-error ang .count())
        class DummyItems:
            def count(self): return 5

        class DummyRequest:
            request_no = "REQ-2026-TEST-99"
            receiving_place = "Assembly Zone A"
            delivery_date = "2026-04-15"
            reason = "Testing Material Request Email"
            items = DummyItems()

        send_test("New Material Request Submitted", "new_material_request.html", {
            'req': DummyRequest()
        })

        # 🚀 12. ASSEMBLY COMPLETED
        class DummyMachine:
            machine_code = "MAC-X900-TEST"
            name = "Industrial Conveyor Belt"

        send_test("Machine Assembly Completed", "assembly_completed.html", {
            'machine': DummyMachine()
        })

        # 13. SHIPPING NOTIFICATION
        send_test("Shipment Dispatched", "shipping_notification_email.html", {
            'order_no': 'SO-2026-005', 'customer_name': 'Beta Tech Corp', 
            'courier': 'LBC Express', 'tracking': 'LBC-123456789'
        })

        # 14. STOCK CORRECTION
        send_test("Manual Stock Correction", "stock_correction_email.html", {
            'lot_no': 'LOT-1002', 'item_code': 'RAW-MAT-X', 
            'old_qty': 100, 'new_qty': 85, 'reason': 'Damaged items disposed.'
        })

        # Success! (In-update ko na to 12)
        messages.success(request, f"MASSIVE SUCCESS! 12 Test Emails with HTML Designs were sent to: {', '.join(target_emails)}. Check your Inbox!")

    except EmailRoute.DoesNotExist:
        messages.error(request, "Test Failed: Please setup the 'TEST_ALERT' event in your Email Routes first.")
    except Exception as e:
        messages.error(request, f"SMTP/Connection Error: {str(e)}")

    return redirect('email_master')