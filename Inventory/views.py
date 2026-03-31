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
from django.db.models import Sum, Count, Q, F    
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.urls import reverse
from django.http import HttpResponseRedirect
from .decorators import allowed_roles
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings as django_settings
from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver
from django.core.cache import cache
from django.conf import settings
from datetime import timedelta
from decimal import Decimal
import pandas as pd
import datetime
import secrets
import string
import random
import uuid
import json
import csv
from .utils import send_shipping_notification, send_order_acknowledgement, send_qc_rejection_alert, log_system_action, notify_admins, send_in_app_notification
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
)

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
    # Kailangan naka-login para makapag-change password
    if not request.user.is_authenticated:
        return redirect('login') # Palitan base sa login url mo

    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # 1. I-check kung tama ang lumang password
        if not request.user.check_password(old_password):
            messages.error(request, "Error: Incorrect old password.")
            return redirect('change_password')
        
        # 2. I-check kung magkaparehas ang bago at confirm password
        if new_password != confirm_password:
            messages.error(request, "Error: New passwords do not match.")
            return redirect('change_password')
            
        # 3. Optional: I-check kung masyadong maiksi ang password
        if len(new_password) < 8:
            messages.error(request, "Error: Password must be at least 8 characters.")
            return redirect('change_password')

        # 4. I-save ang bagong password
        request.user.set_password(new_password)
        request.user.save()
        
        update_session_auth_hash(request, request.user)

#       log_system_action(request.user, 'UPDATE', 'User Security', f"User {request.user.username} changed their password.", request)
        
        messages.success(request, "Success! Your password has been updated securely.")
        return redirect('settings_master') # Pwedeng ibalik sa settings hub o dashboard

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

    # Kunin ang mga Low Stock (halimbawa: 100 pcs pababa)
    low_stock_items = active_tags.filter(total_pcs__lte=100).order_by('total_pcs')[:5]
    
    # Kunin ang mga Expiring within 30 days
    expiring_items = active_tags.filter(expiration_date__lte=thirty_days, expiration_date__gte=today).order_by('expiration_date')[:5]

    # Pagsasamahin natin sa isang listahan para madaling i-display sa HTML
    alerts = []
    for item in low_stock_items:
        alerts.append({
            'item_code': item.item_code,
            'detail': f"{item.total_pcs} PCS remaining",
            'type': 'Low Stock'
        })
    for item in expiring_items:
        days_left = (item.expiration_date - today).days if item.expiration_date else 0
        alerts.append({
            'item_code': item.item_code,
            'detail': f"Expires in {days_left} days",
            'type': 'Expiring'
        })
    
    alert_count = active_tags.filter(total_pcs__lte=100).count() + active_tags.filter(expiration_date__lte=thirty_days, expiration_date__gte=today).count()

    # ---------------------------------------------------------
    # 3. PENDING TASKS / RELEASES (UPDATED PARA SA CUSTOMER ORDERS)
    # ---------------------------------------------------------
    try:
        # Kunin lahat ng pending na Customer Orders
        pending_items = CustomerOrder.objects.filter(order_status='Pending').order_by('order_date')
        
        # Dahil per item ang save natin sa table, i-group natin by Order No
        unique_orders = []
        seen_order_nos = set()
        
        for item in pending_items:
            if item.order_no not in seen_order_nos:
                seen_order_nos.add(item.order_no)
                unique_orders.append({
                    'order_no': item.order_no,
                    'customer': {'name': item.customer.name if item.customer else 'Walk-in'},
                    'quantity': item.quantity  # Pwedeng total items ito, pero item qty na muna
                })

        pending_req_count = len(unique_orders)
        recent_pending_reqs = unique_orders[:5] # Top 5 lang ipapakita sa Dashboard

    except Exception as e:
        print(f"DASHBOARD ERROR: {e}") # Para makita natin sa terminal kung may mali
        pending_req_count = 0
        recent_pending_reqs = []

    # ---------------------------------------------------------
    # 4. IPASA SA TEMPLATE
    # ---------------------------------------------------------
    context = {
        'total_inventory_value': total_inventory_value,
        'total_active_lots': total_active_lots,
        'alerts': alerts,
        'alert_count': alert_count,
        'recent_pending_reqs': recent_pending_reqs,
        'pending_req_count': pending_req_count,
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

@login_required(login_url='login')
def customer_master_view(request):
    # Kukunin natin lahat ng contacts na naka-tag as 'Customer'
    customers_list = Contact.objects.filter(contact_type='Customer').order_by('name')
    
    context = {
        'customers': customers_list
    }
    return render(request, 'Inventory/master/customer_master.html', context)

# 1. ANG VIEW PARA SA TABLE (Master List)
@login_required(login_url='login')
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
            is_active = request.POST.get('is_active') == 'True'
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

def item_master_view(request):
    # ==========================================
    # 1. POST: ADD / EDIT / DELETE ITEM
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

            if Item.objects.filter(item_code=item_code).exists():
                messages.error(request, f"Error: Item Code '{item_code}' already exists!")
            else:
                Item.objects.create(
                    item_code=item_code, description=description,
                    category=category, uom=uom, unit_price=unit_price,
                    min_stock=min_stock, default_zone=default_zone
                )
                log_system_action(request.user, 'CREATE', 'Item Master', f"Registered item: {item_code}", request)
                messages.success(request, f"Success! Item '{item_code}' has been registered.")

        elif action == 'edit':
            item_id = request.POST.get('item_id')
            item_code = request.POST.get('item_code', '').strip().upper()
            
            try:
                item = Item.objects.get(id=item_id)
                # Check for duplicate code if they changed it
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
                    
                    log_system_action(request.user, 'UPDATE', 'Item Master', f"Updated item: {item_code}", request)
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

        return redirect('item_master')

    # ==========================================
    # 2. GET: LOAD PAGE AND SEARCH
    # ==========================================
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

    # 🚀 BAGO: Kunin ang mga Zones mula sa LocationMaster para sa Dropdown sa Modal
    zones = LocationMaster.objects.values_list('zone', flat=True).distinct()
    zone_list = [z for z in zones if z] # Tanggalin ang mga blank zones

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

def settings_master_view(request):
    # Ito ang magiging main hub menu
    return render(request, 'Inventory/master/settings_master.html')

def item_master(request):
    search_query = request.GET.get('q', '')
    items = Item.objects.all().order_by('item_code')
    
    if search_query:
        items = items.filter(
            Q(item_code__icontains=search_query) | 
            Q(description__icontains=search_query)
        )
    
    return render(request, 'Inventory/master/item_master.html', {
        'items': items,
        'search_query': search_query
    })

def register_item(request):
    if request.method == "POST":
        # Kunin ang data mula sa form (Register Item UI natin kanina)
        item_code = request.POST.get('item_code')
        description = request.POST.get('description')
        uom = request.POST.get('uom')
        category = request.POST.get('category')
        min_stock = request.POST.get('min_stock', 0)

        # Check kung existing na
        if Item.objects.filter(item_code=item_code).exists():
            messages.error(request, f"Item Code {item_code} is already registered.")
        else:
            Item.objects.create(
                item_code=item_code,
                description=description,
                uom=uom,
                category=category,
                min_stock=min_stock
            )

            log_system_action(request.user, 'CREATE', 'Item Master', f"Registered new item: {item_code} ({description})", request)

            messages.success(request, f"Item {item_code} successfully added to Masterlist.")
            return redirect('item_code_master')

    return render(request, 'Inventory/master/register_item.html')

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
def order_input_manual_view(request):
    if request.method == "POST":
        # 1. Kunin lahat ng headers (Main at Sub Orders) as Arrays
        customers = request.POST.getlist('customer_name')
        order_nos = request.POST.getlist('in_order_no')
        contact_persons = request.POST.getlist('contact_person')
        delivery_addresses = request.POST.getlist('delivery_input')
        order_types = request.POST.getlist('order_type')
        cust_po_nos = request.POST.getlist('cust_po_no')
        transports = request.POST.getlist('transport_main')
        order_statuses = request.POST.getlist('order_status')
        order_contents_list = request.POST.getlist('order_contents')
        remarks_list = request.POST.getlist('remarks_main')

        # Static Date (Iisang date lang para sa buong batch creation based sa design mo)
        order_date = request.POST.get('order_date')

        batch_orders = []

        try:
            # 2. I-loop ang bawat customer order form
            for i in range(len(customers)):
                cust_name = customers[i].strip()
                if not cust_name: continue

                # Alamin kung main table ba (index 0) o idinagdag na table
                if i == 0:
                    item_codes = request.POST.getlist('item_code[]')
                    cust_item_codes = request.POST.getlist('cust_item_code[]')
                    descriptions = request.POST.getlist('description[]') 
                    del_dates = request.POST.getlist('del_date[]') 
                    row_transports = request.POST.getlist('transport[]') 
                    qtys = request.POST.getlist('qty[]')
                    units = request.POST.getlist('unit[]')
                    prices = request.POST.getlist('price[]')
                    row_statuses = request.POST.getlist('status[]')
                else:
                    item_codes = request.POST.getlist(f'item_code_{i}[]')
                    cust_item_codes = request.POST.getlist(f'cust_item_code_{i}[]')
                    descriptions = request.POST.getlist(f'description_{i}[]') 
                    del_dates = request.POST.getlist(f'del_date_{i}[]') 
                    row_transports = request.POST.getlist(f'transport_{i}[]') 
                    qtys = request.POST.getlist(f'qty_{i}[]')
                    units = request.POST.getlist(f'unit_{i}[]')
                    prices = request.POST.getlist(f'price_{i}[]')
                    row_statuses = request.POST.getlist(f'status_{i}[]')

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
                            'cust_item_code': cust_item_codes[j] if j < len(cust_item_codes) else "",
                            'description': descriptions[j] if j < len(descriptions) else "", 
                            'del_date': del_dates[j] if j < len(del_dates) else order_date, 
                            'transport': row_transports[j] if j < len(row_transports) else "Truck", 
                            'qty': qty,
                            'unit': units[j] if j < len(units) else "PCS",
                            'price': price,
                            'amount': amount,
                            'status': row_statuses[j] if j < len(row_statuses) else "Pending"
                        })
                
                # 3. Ipunin sa isang Dictionary bawat isang Customer Order
                batch_orders.append({
                    'header': {
                        'order_no': order_nos[i] if i < len(order_nos) else f"SO-AUTO-{i}",
                        'customer': cust_name,
                        'contact_person': contact_persons[i] if i < len(contact_persons) else "",
                        'delivery_address': delivery_addresses[i] if i < len(delivery_addresses) else "",
                        'date': order_date,
                        'order_type': order_types[i] if i < len(order_types) else "Standard",
                        'cust_po_no': cust_po_nos[i] if i < len(cust_po_nos) else "",
                        'order_contents': order_contents_list[i] if i < len(order_contents_list) else "",
                        'status': order_statuses[i] if i < len(order_statuses) else "Pending",
                        'transport': transports[i] if i < len(transports) else "Truck",
                        'remarks': remarks_list[i] if i < len(remarks_list) else "",
                        'grand_total': subtotal
                    },
                    'items': order_items
                })

        except Exception as e:
            # Handle list index out of bounds or parsing errors safely
            print("Error parsing batch orders:", str(e))
            return redirect('order_manual')

        # 4. I-SAVE SA SESSION (Para sa Confirmation Page)
        # Papalitan natin ng batch ang session imbes na isahan
        request.session['batch_customer_orders'] = batch_orders
        
        return redirect('po_confirmation') # Pwede mo itong palitan ng 'order_confirmation' sa susunod mong module

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

        # Hindi batch, iisang order lang
        pending_order = {
            'header': {
                'order_no': order_no,
                'customer': cust_name,
                'contact_person': request.POST.get('contact_person', ''),
                'delivery_address': request.POST.get('delivery_input', ''),
                'date': request.POST.get('order_date'),
                'order_type': request.POST.get('order_type', 'Standard'),
                'cust_po_no': request.POST.get('cust_po_no', ''),
                'status': request.POST.get('order_status', 'Pending'),
                'transport': request.POST.get('transport_main', 'Truck'),
                'grand_total': grand_total
            },
            'items': order_items
        }

        # Dahil tinanggal natin sa batch format, pwede mo itong ipasa na nakabalot 
        # sa array na iisa ang laman para parehas sila ng format nung Order Manual view, 
        # o kaya gumawa ng separate session key para dito. 
        # (Naka-batch structure pero isang laman para iisa lang ang Confirmation page code mo)
        request.session['batch_customer_orders'] = [pending_order]

        return redirect('po_confirmation') # Pwede mong palitan ito sa tamang url path

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

                    # 3. I-loop at i-save ang bawat item bilang CustomerOrder (Base sa model mo)
                    # NOTE: Mapapansin mo na hiwa-hiwalay yung pag-save mo sa CustomerOrder per item. 
                    # Ito yung structure na ginawa mo kaya sinunod ko.
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
                    
                    # 4. System Logs & Email (Maa-apply per order)
                    action_type = 'UPDATE' if header.get('is_correction') else 'CREATE'
                    # log_system_action(...) # I-uncomment mo kung meron kang logger
                    
                    customer_email = getattr(customer_obj, 'email', None) 
                    send_email_flag = request.POST.get('send_email') 
                    
                    if send_email_flag == 'on' and customer_email:
                        pass
                        # send_order_acknowledgement(...) # I-uncomment mo ito

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
    return render(request, 'Inventory/customer_order/PO_Confirmation.html', {
        'batch_orders': batch_orders,
    })

def order_correction_view(request):
    context = {}

    # ==========================================
    # 1. KUNG PININDOT ANG "SAVE CORRECTIONS" (POST)
    # ==========================================
    if request.method == "POST":
        batch_ref = request.POST.get('batch_ref')
        correction_reason = request.POST.get('correction_reason')
        
        # Kunin ang mga in-edit na data mula sa table rows
        item_ids = request.POST.getlist('item_id[]')
        qtys = request.POST.getlist('qty_row[]')
        unit_prices = request.POST.getlist('price_row[]')
        amounts = request.POST.getlist('amount_row[]')

        try:
            with transaction.atomic():
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_log = f"\n[CORRECTED on {current_time}] Reason: {correction_reason}"

                # I-loop at i-update ang bawat Item na nasa table gamit ang ID
                for i in range(len(item_ids)):
                    item = CustomerOrder.objects.get(id=item_ids[i])
                    item.quantity = qtys[i]
                    item.unit_price = unit_prices[i]
                    item.amount = amounts[i]
                    
                    # Ibalik sa 'Pending' ang status at idikit ang reason sa remarks
                    item.order_status = 'Pending'
                    item.remarks = str(item.remarks or "") + audit_log
                    item.save() 

            messages.success(request, f"Success! Order Batch {batch_ref} has been corrected and sent back to Pending status.")
            # Palitan ng tamang url name kung saan mo gusto pumunta after save (e.g., 'order_inquiry')
            return redirect('dashboard') 

        except Exception as e:
            messages.error(request, f"Error updating database: {str(e)}")
            return redirect(f'/customer-order/correction/?search_order={batch_ref}')

    # ==========================================
    # 2. KUNG NAG-SEARCH NG ORDER NUMBER (GET)
    # ==========================================
    search_query = request.GET.get('search_order', '').strip()
    
    if search_query:
        # Hanapin muna kung nag-e-exist yung Order
        base_items = CustomerOrder.objects.filter(order_no=search_query)
        
        if base_items.exists():
            first_item = base_items.first()
            
            # Alamin kung may batch_id para mahugot ang kasama. Kung wala, order_no lang.
            if hasattr(first_item, 'batch_id') and first_item.batch_id:
                batch_ref = first_item.batch_id
                all_items = CustomerOrder.objects.filter(batch_id=batch_ref).order_by('id')
            else:
                batch_ref = first_item.order_no
                all_items = base_items.order_by('id')

            # I-Group ang items by Order No para madaling i-loop sa HTML
            order_dict = {}
            for item in all_items:
                if item.order_no not in order_dict:
                    order_dict[item.order_no] = {
                        'header': {
                            'order_no': item.order_no,
                            'customer': item.customer.name if item.customer else '',
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
            context['searched'] = True
            
        else:
            messages.error(request, f"Order '{search_query}' not found.")
            context['searched'] = False

    # Kunin lahat ng kailangan ng HTML
    context['search_query'] = search_query
    context['customers'] = Contact.objects.filter(contact_type='Customer').order_by('name')
    context['all_items'] = Item.objects.all().order_by('item_code')

    return render(request, 'Inventory/customer_order/Order_Correction.html', context)

def order_inquiry_view(request):
    search_query = request.GET.get('search', '').strip()
    
    # 1. Kunin lahat ng items
    qs = CustomerOrder.objects.all().order_by('-order_date', '-id')
    
    if search_query:
        qs = qs.filter(
            Q(order_no__icontains=search_query) |
            Q(customer__name__icontains=search_query) |
            Q(batch_id__icontains=search_query)
        )

    batches_dict = {}
    
    # 🚀 BAGO: Variables para sa mga Summary Cards natin
    overall_grand_total = 0.0
    
    for item in qs:
        bid = getattr(item, 'batch_id', item.order_no) or item.order_no
        
        if bid not in batches_dict:
            batches_dict[bid] = {}
        
        if item.order_no not in batches_dict[bid]:
            batches_dict[bid][item.order_no] = {
                'header': {
                    'order_no': item.order_no,
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
        
        batches_dict[bid][item.order_no]['items'].append(item)
        
        # Pera computation
        amount = float(item.amount or 0)
        batches_dict[bid][item.order_no]['header']['grand_total'] += amount
        overall_grand_total += amount # Idagdag sa overall total

    batch_list = []
    for bid, orders_in_batch in batches_dict.items():
        order_list = list(orders_in_batch.values())
        main_order = order_list[0] 
        
        batch_grand_total = sum(o['header']['grand_total'] for o in order_list)
        total_items_in_batch = sum(len(o['items']) for o in order_list)
        
        batch_list.append({
            'batch_id': bid,
            'main_order': main_order,
            'all_orders': order_list, 
            'sub_orders_count': len(order_list) - 1,
            'batch_grand_total': batch_grand_total,
            'total_items': total_items_in_batch
        })

    # 🚀 BAGO: Bilangin ang mga specific statuses para sa Cards
    total_orders_count = qs.values('order_no').distinct().count()
    total_pending = qs.filter(order_status='Pending').values('order_no').distinct().count()
    total_delivered = qs.filter(order_status='Delivered').values('order_no').distinct().count()

    # Pagination
    paginator = Paginator(batch_list, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'items': page_obj, 
        'search_query': search_query,
        
        # 🚀 BAGO: Ipasa ang mga na-compute sa HTML
        'overall_grand_total': overall_grand_total,
        'total_orders_count': total_orders_count,
        'total_pending': total_pending,
        'total_delivered': total_delivered,
    }
    return render(request, 'Inventory/customer_order/Order_Inquiry.html', context)

def order_dispatch_view(request, order_no):
    items = CustomerOrder.objects.filter(order_no=order_no, order_status='Pending')
    
    if not items.exists():
        messages.error(request, "Order not found or already dispatched.")
        return redirect('dashboard')

    if request.method == "POST":
        courier = request.POST.get('courier')
        tracking = request.POST.get('tracking')

        try:
            with transaction.atomic():
                for item in items:
                    qty_to_deduct = item.quantity
                    
                    # FIFO Logic
                    tags = MaterialTag.objects.filter(
                        item_code=item.item_code, 
                        total_pcs__gt=0
                    ).order_by('expiration_date', 'id')

                    for tag in tags:
                        if qty_to_deduct <= 0: break
                        
                        deduct = min(tag.total_pcs, qty_to_deduct)
                        old_qty = tag.total_pcs
                        tag.total_pcs -= deduct
                        tag.save()

                        # Record to Stock History
                        StockLog.objects.create(
                            material_tag=tag,
                            action_type='OUT',
                            old_qty=old_qty,
                            change_qty=-deduct,
                            new_qty=tag.total_pcs,
                            notes=f"Dispatched Order #{order_no}",
                            user=request.user
                        )
                        qty_to_deduct -= deduct

                    if qty_to_deduct > 0:
                        raise ValueError(f"Insufficient stock for {item.item_code}.")

                # 🚀 FIX: KUNIN ANG EMAIL BAGO MAG-UPDATE NG STATUS
                first_item = items.first()
                customer_email = None
                if first_item and first_item.customer:
                    customer_email = getattr(first_item.customer, 'email', None)

                # 🚀 UPDATE STATUS
                items.update(
                    order_status='Shipped',
                    transport=courier,
                    remarks=f"TRK: {tracking}"
                )

                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Customer Order', 
                    description=f"Dispatched Order {order_no} via {courier} (Tracking: {tracking})", 
                    request=request
                )

                # 🚀 SEND EMAIL
                if customer_email:
                    send_shipping_notification(order_no, customer_email, courier, tracking)

                messages.success(request, f"Order #{order_no} dispatched successfully!")
                return redirect('order_inquiry') # Pabalik sa Inquiry listahan natin

        except Exception as e:
            messages.error(request, str(e))
            return redirect('order_dispatch', order_no=order_no)

    context = {
        'order_no': order_no,
        'items': items,
        'customer_name': items.first().customer.name if items.first().customer else "Walk-in"
    }
    return render(request, 'Inventory/customer_order/order_dispatch.html', context)

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
def make_po_view(request):
    if request.method == "POST":
        # Arrays ng headers (Main form at yung mga in-add)
        suppliers = request.POST.getlist('supplier')
        po_nos = request.POST.getlist('po_no')
        tax_terms = request.POST.getlist('tax_term')
        order_statuses = request.POST.getlist('ordering_status')

        # Static variables (Manggagaling lang lahat sa pinakaunang main form)
        order_date = request.POST.get('order_date')
        delivery_date = request.POST.get('delivery_date')
        transport = request.POST.get('transport', 'Truck')
        currency = request.POST.get('currency', 'PHP')
        discount_rate = float(request.POST.get('discount_rate') or 0.0)
        remarks = request.POST.get('remarks', '')

        # Dahil ito ay Original logic mo na nagse-save sa "session" bago i-confirm
        # Iipunin natin lahat sa isang listahan
        batch_pos = []

        try:
            for i in range(len(suppliers)):
                supp_name = suppliers[i].strip()
                if not supp_name: continue

                # Alamin kung aling table yung huhugutan ng data
                if i == 0:
                    item_codes = request.POST.getlist('item_code[]')
                    descriptions = request.POST.getlist('description[]')
                    packings = request.POST.getlist('packing[]')
                    moqs = request.POST.getlist('moq[]')
                    qtys = request.POST.getlist('qty[]')
                    unit_prices = request.POST.getlist('unit_price[]')
                    row_amounts = request.POST.getlist('row_amount[]')
                    amortizations = request.POST.getlist('amortization[]')
                else:
                    item_codes = request.POST.getlist(f'item_code_{i}[]')
                    descriptions = request.POST.getlist(f'description_{i}[]')
                    packings = request.POST.getlist(f'packing_{i}[]')
                    moqs = request.POST.getlist(f'moq_{i}[]')
                    qtys = request.POST.getlist(f'qty_{i}[]')
                    unit_prices = request.POST.getlist(f'unit_price_{i}[]')
                    row_amounts = request.POST.getlist(f'row_amount_{i}[]')
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
                discount_amount = subtotal * (discount_rate / 100)
                net_subtotal = subtotal - discount_amount
                tax_amount = net_subtotal * 0.12 if tax_term in ['VAT Inclusive', 'Taxable'] else 0.0
                grand_total = net_subtotal + tax_amount

                # Ipunin lahat per supplier request
                batch_pos.append({
                    'header': {
                        'po_no': po_nos[i],
                        'supplier': supp_name,
                        'order_date': order_date,
                        'delivery_date': delivery_date,
                        'transport': transport,
                        'tax_term': tax_term,
                        'currency': currency,
                        'discount_rate': discount_rate,
                        'status': order_statuses[i] if i < len(order_statuses) else 'Valid',
                        'remarks': remarks if i == 0 else '',
                        'subtotal': subtotal,
                        'discount_amount': discount_amount,
                        'tax_amount': tax_amount,
                        'grand_total': grand_total
                    },
                    'items': po_items
                })

            # I-save natin sa Session at i-redirect sa Confirm Page
            # Note: I-uupdate mo rin yung po_confirm_purchase HTML mo para mabasa niya yung multiple batch_pos na 'to!
            request.session['batch_pos'] = batch_pos
            return redirect('po_confirm_purchase')

        except Exception as e:
            messages.error(request, f"Error processing batch: {str(e)}")
            return redirect('make_po')

    # GET Request
    suppliers_list = Supplier.objects.all().order_by('name')
    items_list = Item.objects.all().order_by('item_code')
    return render(request, 'Inventory/purchase_order/supplier_po.html', {
        'suppliers': suppliers_list,
        'items': items_list,
    })

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
        'main_po': base_po, # Reference para sa Main Toolbar / File Name
    }
    return render(request, 'Inventory/purchase_order/print_po.html', context)

def api_get_item_details(request):
    """ Server-side API para kunin ang detalye at presyo ng ISANG item """
    item_code = request.GET.get('item_code', '').strip()
    
    if not item_code:
        return JsonResponse({'success': False, 'error': 'No item code provided.'})

    try:
        # Hahanapin natin yung mismong item
        item = Item.objects.get(item_code=item_code)
        
        # Ibabato pabalik sa Javascript yung data
        return JsonResponse({
            'success': True,
            'description': item.description or '',
            'unit_price': item.unit_price or 0.00,
            'uom': item.uom or 'PCS'
        })
    except Item.DoesNotExist:
        # Kung mali ang tinype na item code
        return JsonResponse({'success': False, 'error': 'Item not found.'})

def po_confirm_purchase_view(request):
    # ==========================================
    # 1. KUNG PININDOT ANG "SAVE TO DATABASE" (POST)
    # ==========================================
    if request.method == "POST":
        batch_pos = request.session.get('batch_pos')

        if not batch_pos:
            messages.error(request, "Session expired or no data found. Please try again.")
            return redirect('make_po')

        try:
            with transaction.atomic():
                # === LOGIC PARA SA BATCH ID ===
                current_batch_id = f"BATCH-{uuid.uuid4().hex[:6].upper()}"

                for po_data in batch_pos:
                    header = po_data.get('header')
                    items = po_data.get('items')

                    # === LOGIC PARA SA SUPPLIER LANG ===
                    supplier_name = header.get('supplier')
                    supplier_obj = None
                    if supplier_name:
                        # Gumawa ng temporary na Vendor Code (e.g., "VND-A1B2C3")
                        temp_vendor_code = f"VND-{uuid.uuid4().hex[:6].upper()}"
                        
                        # Auto-create supplier kung wala pa, at ipasa ang default vendor code
                        supplier_obj, created = Supplier.objects.get_or_create(
                            name=supplier_name,
                            defaults={'vendor_code': temp_vendor_code}
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
                        tax_term=header.get('tax_term', 'Vat Inc'),
                        currency=header.get('currency', 'PHP'),
                        delivery_date=header.get('delivery_date') if header.get('delivery_date') else None,
                        discount_rate=header.get('discount_rate', 0.00),
                        remarks=header.get('remarks', ''),
                        
                        # 🚀 FIX: Hardcode natin as 'Pending Approval' para pumasok sa Approval Queue
                        ordering_status='Pending Approval', 
                        
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

                    # --- Mga Logs ---
                    log_system_action(
                        user=request.user,
                        action='CREATE',
                        module='Purchase Order',
                        description=f"Created new Purchase Order: {new_po.po_no} for Supplier: {supplier_obj.name}",
                        request=request
                    )

            # Notifications
            notify_admins(
                title="📄 New P.O.(s) For Approval",
                message=f"{request.user.username} created {len(batch_pos)} PO(s). Pending your approval.",
                link="/purchase-order/approve/" 
            )

            # C. Linisin ang Session
            del request.session['batch_pos']

            messages.success(request, f"Success! {len(batch_pos)} Purchase Order(s) saved.")
            return redirect('approve_po') 

        except Exception as e:
            print("=========================================")
            print("BOMBA SA DATABASE (CONFIRM PO):", str(e))
            print("=========================================")
            messages.error(request, f"Error saving to database: {str(e)}")
            return redirect('po_confirm_purchase')

    # ==========================================
    # 2. KUNG PAG-LOAD LANG NG PAGE (GET)
    # ==========================================
    batch_pos = request.session.get('batch_pos')
    
    if not batch_pos:
        messages.warning(request, "No pending Purchase Order to confirm. Create one first.")
        return redirect('make_po')

    context = {
        'batch_pos': batch_pos,
    }
    
    return render(request, 'Inventory/purchase_order/PO_Confirmation.html', context)
    
def approve_po_view(request):
    if request.method == "POST":
        # 🚀 BAGO: Batch ID na ang gagamitin natin para sabay-sabay ma-approve
        batch_id = request.POST.get('batch_id')
        action = request.POST.get('action') 

        if batch_id:
            pos_to_update = PurchaseOrder.objects.filter(batch_id=batch_id)
            new_status = 'Approved' if action == 'approve' else 'Cancelled'
            
            # I-update lahat ng P.O. sa ilalim ng batch na ito
            pos_to_update.update(ordering_status=new_status)
            
            if action == 'approve':
                messages.success(request, f"Batch {batch_id} has been APPROVED.")
            else:
                messages.error(request, f"Batch {batch_id} has been REJECTED.")
                
        return redirect('approve_po')

    # ==========================================
    # GET REQUEST / LOADING THE PAGE
    # ==========================================
    pending_qs = PurchaseOrder.objects.filter(
        ordering_status='Pending Approval'
    ).prefetch_related('items').order_by('id')

    # 🚀 BAGO: I-group ang mga P.O. by Batch ID
    batches_dict = {}
    for po in pending_qs:
        bid = po.batch_id if po.batch_id else po.po_no # Fallback kung sakaling walang batch_id yung luma
        if bid not in batches_dict:
            batches_dict[bid] = []
        batches_dict[bid].append(po)

    grouped_batches = []
    for bid, pos in batches_dict.items():
        main_po = pos[0] # Ang pinakauna ay laging ang Main P.O.
        batch_grand_total = sum(p.grand_total for p in pos)
        grouped_batches.append({
            'batch_id': bid,
            'main_po': main_po,
            'sub_pos': pos[1:], # Ang mga sumunod ay ang mga Sub P.O.
            'all_pos': pos,
            'total_pos': len(pos),
            'batch_grand_total': batch_grand_total
        })

    # KPI Cards Logic
    today = timezone.now().date()
    # Bilangin ang distinct batches imbes na individual POs
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
    # Gumagamit tayo ng aggregate para mabilis ang computation ng Pera
    overall_grand_total = po_qs.aggregate(total=Sum('grand_total'))['total'] or 0.00
    
    total_orders_count = po_qs.count()
    total_pending = po_qs.filter(ordering_status__in=['Pending Approval', 'Pending']).count()
    total_approved = po_qs.filter(ordering_status='Approved').count()

    # 4. I-group ang mga na-filter na POs by Batch ID
    batches_dict = {}
    for po in po_qs:
        bid = getattr(po, 'batch_id', po.po_no) or po.po_no
        if bid not in batches_dict:
            batches_dict[bid] = []
        batches_dict[bid].append(po)

    grouped_batches = []
    for bid, pos in batches_dict.items():
        main_po = pos[0]
        batch_grand_total = sum(float(p.grand_total or 0) for p in pos)
        grouped_batches.append({
            'batch_id': bid,
            'main_po': main_po,
            'sub_pos': pos[1:],
            'all_pos': pos,
            'total_pos': len(pos),
            'batch_grand_total': batch_grand_total
        })

    # 5. Pagination (I-paginate natin yung grouped list)
    paginator = Paginator(grouped_batches, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'from_date': from_date,
        'to_date': to_date,
        
        # 🚀 BAGO: Ipasa ang mga na-compute sa HTML Cards
        'overall_grand_total': overall_grand_total,
        'total_orders_count': total_orders_count,
        'total_pending': total_pending,
        'total_approved': total_approved,
    }
    
    return render(request, 'Inventory/purchase_order/PO_Inquiry.html', context)

def po_correction_view(request):
    context = {}

    # ==========================================
    # 1. KUNG PININDOT ANG "SAVE CORRECTIONS" (POST)
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
                # A. I-update ang lahat ng Items na na-edit
                for i in range(len(item_ids)):
                    item = PurchaseOrderItem.objects.get(id=item_ids[i])
                    item.qty = qtys[i]
                    item.unit_price = unit_prices[i]
                    item.amount = amounts[i]
                    item.save()

                # B. Hanapin ang lahat ng P.O. sa batch na ito (o yung iisang P.O.)
                if batch_ref.startswith('BATCH-'):
                    pos_to_update = PurchaseOrder.objects.filter(batch_id=batch_ref)
                else:
                    pos_to_update = PurchaseOrder.objects.filter(po_no=batch_ref)
                
                # C. I-log at i-recompute ang totals ng Bawat P.O.
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_log = f"\n[CORRECTED on {current_time}] Reason: {correction_reason}"
                
                for po in pos_to_update:
                    # I-update ang Status at Remarks
                    po.remarks = str(po.remarks or "") + audit_log
                    po.ordering_status = 'Pending Approval'
                    
                    # 🚀 RECOMPUTE TOTALS SA HEADER DAHIL NAGBAGO ANG ITEMS
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

            # log system action (I-uncomment mo kung may log_system_action ka)
            # log_system_action(...)

            messages.success(request, f"Success! Batch/PO {batch_ref} has been corrected and sent back for approval.")
            return redirect('po_inquiry')

        except Exception as e:
            messages.error(request, f"Error updating database: {str(e)}")
            return redirect(f'/purchase-order/correction/?search_po={batch_ref}')

    # ==========================================
    # 2. KUNG NAG-SEARCH NG PO NUMBER (GET)
    # ==========================================
    if request.method == "GET" and 'search_po' in request.GET:
        po_no_query = request.GET.get('search_po').strip()
        
        try:
            # Hanapin yung mismong PO na tinype
            searched_po = PurchaseOrder.objects.get(po_no=po_no_query)
            
            # 🚀 BAGO: Kung may batch_id siya, kunin ang buong batch!
            if searched_po.batch_id:
                po_list = PurchaseOrder.objects.filter(batch_id=searched_po.batch_id).prefetch_related('items').order_by('id')
                batch_ref = searched_po.batch_id
            else:
                # Kung lumang PO na walang batch, kunin na lang mag-isa
                po_list = [searched_po]
                batch_ref = searched_po.po_no
            
            context['po_list'] = po_list
            context['batch_ref'] = batch_ref
            context['searched'] = True
            
        except PurchaseOrder.DoesNotExist:
            messages.error(request, f"Purchase Order '{po_no_query}' not found in database.")
            context['searched'] = False

    return render(request, 'Inventory/purchase_order/PO_Correction.html', context)

# Receiving / Inspection 
def ri_receive_view(request):
    context = {'searched': False}

    # ==========================================
    # 1. GET: PAG-SCAN NG PO BARCODE
    # ==========================================
    if request.method == "GET" and 'search_po' in request.GET:
        po_no_query = request.GET.get('search_po').strip()
        try:
            po_header = PurchaseOrder.objects.get(po_no=po_no_query)
            
            # Check if it's already fully received
            if po_header.ordering_status == 'Received':
                messages.warning(request, f"PO '{po_no_query}' has already been fully received.")
            elif po_header.ordering_status != 'Approved':
                messages.warning(request, f"PO '{po_no_query}' is currently '{po_header.ordering_status}'. Only 'Approved' POs can be received.")
            else:
                context['po_header'] = po_header
                context['po_items'] = po_header.items.all()
                context['searched'] = True
        except PurchaseOrder.DoesNotExist:
            messages.error(request, f"Purchase Order '{po_no_query}' not found in the database.")

    # ==========================================
    # 2. POST: PAG-SAVE SA DATABASE (Receiving Confirmation Only)
    # ==========================================
    if request.method == "POST":
        po_no = request.POST.get('po_no')
        delivery_date = request.POST.get('delivery_date') # Added this since it's in your HTML

        try:
            with transaction.atomic():
                po_header = PurchaseOrder.objects.get(po_no=po_no)
                
                items_received_count = 0
                all_items_fully_received = True

                # I-loop lahat ng items sa PO para i-update ang received qty
                for item in po_header.items.all():
                    qty_received_str = request.POST.get(f'qty_received_{item.id}')
                    
                    if qty_received_str:
                        qty_received = int(qty_received_str)
                        if qty_received > 0:
                            # Update the item's received quantity (Assume you have a qty_received field in your PO Item model)
                            # If you don't have qty_received in PurchaseOrderItem, you should add it!
                            if hasattr(item, 'qty_received'):
                                item.qty_received = (item.qty_received or 0) + qty_received
                                item.save()
                            
                            items_received_count += 1

                            # Check if the item is fully received
                            # Assuming item.qty is the ordered amount
                            if hasattr(item, 'qty_received') and hasattr(item, 'qty'):
                                if item.qty_received < item.qty:
                                    all_items_fully_received = False

                if items_received_count > 0:
                    # Update the main PO status
                    # If all items are received, mark as 'Received', else 'Partial'
                    po_header.ordering_status = 'Received' if all_items_fully_received else 'Partial'
                    
                    # Optionally save the actual delivery date if you have that field
                    if hasattr(po_header, 'actual_delivery_date') and delivery_date:
                        po_header.actual_delivery_date = delivery_date
                        
                    po_header.save()

                    log_system_action(
                        user=request.user, 
                        action='UPDATE', 
                        module='Receiving', 
                        description=f"Confirmed receipt of {items_received_count} items for PO {po_no}.", 
                        request=request
                    )

                    messages.success(request, f"Success! {items_received_count} items from {po_no} have been marked as received. Proceed to Material Tagging.")
                    
                    # 🚀 Redirect them to the Material Tag generator with the PO number pre-filled!
                    return redirect(f"{reverse('material_tag')}?po_no={po_no}") 
                    
                else:
                    messages.warning(request, "No items were checked for receiving. Please ensure quantity is greater than zero.")

        except Exception as e:
            messages.error(request, f"Error processing receipt: {str(e)}")

    return render(request, 'Inventory/receiving/RI_receive.html', context)

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
                # I-save ang Main Header
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

                # I-save ang bawat Item sa Table
                for i in range(len(item_codes)):
                    # I-skip kung empty ang item_code
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

            alert_new_delivery_request(new_request)

            # 5. Success Message (Dito kukunin ng JS yung REQ No. para sa Print)
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
        'suppliers': Supplier.objects.all().order_by('name'),
        'all_items': Item.objects.all().order_by('item_code') 
    }
    return render(request, 'Inventory/receiving/RI_delivery_request.html', context)

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

# 1. API para sa Stock Search (Tatawagin ng JavaScript)
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

def ri_material_tag_view(request):
    if request.method == 'POST':
        po_nos = request.POST.getlist('po_no[]')
        item_codes = request.POST.getlist('item_code[]')
        descriptions = request.POST.getlist('description[]')
        
        # 🚀 FIX: Kinukuha natin ang Revision at Invoice mula sa Form!
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
                    tag = MaterialTag.objects.create(
                        po_reference=po_ref,
                        item_code=item_codes[i],
                        description=descriptions[i], 
                        lot_no=lot_nos[i].upper(), 
                        
                        # 🚀 DITO PUMASOK ANG INVOICE AT REVISION
                        revision=revisions[i] if i < len(revisions) else '',
                        invoice_no=invoices[i] if i < len(invoices) else '', # Siguraduhing may invoice_no field ka sa models.py
                        
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

def get_item_details(request):
    # Kinuha ko yung 'code' na pangalan mo para mas maikli
    code = request.GET.get('code', '').strip() 
    
    # Yung magandang logic mo
    item = Item.objects.filter(item_code=code).first() 
    
    if item:
        return JsonResponse({
            'success': True,
            'description': item.description,
            # 🚀 DINAGDAG: Kailangan natin 'yung price para sa PO table auto-fill
            'unit_price': float(item.unit_price) if hasattr(item, 'unit_price') else 0.00, 
            'supplier': 'INTERNAL STOCK' # Galing sa code mo
        })
        
    return JsonResponse({'success': False})

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

def get_po_for_tag(request):
    """ Hahanapin nito ang PO number na ita-type mo sa Material Tag page """
    po_no_query = request.GET.get('po_no', '').strip()
    
    if not po_no_query:
        return JsonResponse({'success': False, 'error': 'Please enter a PO Number.'})

    try:
        # Hanapin ang PO sa database
        po_header = PurchaseOrder.objects.get(po_no=po_no_query)
        items = po_header.items.all()
        
        # Kunin ang supplier name nang safe
        supplier_name = "Unknown Supplier"
        if hasattr(po_header, 'supplier') and po_header.supplier:
            # Gagamitin natin ang str() para automatic niyang kunin kung ano ang default name sa Contact model mo
            supplier_name = str(po_header.supplier)
            
        data_list = []
        for item in items:
            data_list.append({
                'item_code': item.item_code,
                'description': item.description if item.description else "No Description",
                'po_no': po_header.po_no,
                'supplier': supplier_name,
                'qty': item.qty,  
                'arrival_date': timezone.now().strftime('%Y-%m-%d'),
            })
            
        return JsonResponse({'success': True, 'items': data_list})
        
    except PurchaseOrder.DoesNotExist:
        return JsonResponse({'success': False, 'error': f'Purchase Order {po_no_query} not found!'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

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

def ri_storage_view(request):
    # AUTO-GENERATE SAMPLES KUNG WALANG LAMAN ANG DATABASE
    if not Location.objects.exists():
        Location.objects.bulk_create([
            Location(place_name='MAIN WAREHOUSE', rack_bin='RACK-A1'),
            Location(place_name='MAIN WAREHOUSE', rack_bin='RACK-A2'),
            Location(place_name='MAIN WAREHOUSE', rack_bin='RACK-B1'),
            Location(place_name='TEMP STORAGE', rack_bin='PALLET-01'),
        ])
        print("Sample locations created!") # Debugging log para sa terminal mo

    # Kunin lahat ng locations para sa dropdown
    locations = LocationMaster.objects.all().order_by('zone', 'location_code')
    
    return render(request, 'Inventory/receiving/RI_storage.html', {'locations': locations})

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

def api_get_material_tag(request):
    lot_no = request.GET.get('lot_no', '').strip().upper()
    
    if not lot_no:
        return JsonResponse({'success': False, 'error': 'No Lot Number provided.'})

    try:
        # 🚀 FIX: Gumamit ng .filter() imbes na .get() para makuha lahat ng kaparehong Lot No
        tags = MaterialTag.objects.filter(lot_no=lot_no)
        
        if not tags.exists():
            return JsonResponse({'success': False, 'error': f'Material Tag (Lot: {lot_no}) not found in database.'})

        # Kunin ang impormasyon mula sa unang box (dahil pareho lang naman sila ng details)
        first_tag = tags.first()
        po_no = first_tag.po_reference.po_no if first_tag.po_reference else "N/A"
        
        # 🚀 FIX: Pagsamahin (SUM) ang bilang ng lahat ng boxes sa Batch na ito
        total_batch_qty = sum(t.total_pcs for t in tags)
        
        # Para luminis ang description sa screen (Tatanggalin ang [Box 1 of 10] sa display)
        import re
        clean_desc = re.sub(r'\[Box \d+ of \d+\]', '', first_tag.description).strip()

        return JsonResponse({
            'success': True,
            'tag': {
                'item_code': first_tag.item_code,
                'description': clean_desc, 
                'po_no': po_no,
                'invoice': first_tag.invoice_no if first_tag.invoice_no else '---', 
                'revision': first_tag.revision if first_tag.revision else '---',
                'arrival_date': first_tag.arrival_date.strftime('%Y-%m-%d') if first_tag.arrival_date else '-',
                'qty': total_batch_qty, # 🚀 Ipapakita sa screen ang total ng buong batch!
                'current_loc': first_tag.location.location_code if first_tag.location else 'UNASSIGNED',
                'invoice': first_tag.invoice_no if hasattr(first_tag, 'invoice_no') else 'N/A', 
                'status': first_tag.inspection_status if hasattr(first_tag, 'inspection_status') else 'PENDING'
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

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
def ri_picking_view(request):
    if request.method == "POST":
        req_no = request.POST.get('scan_request_no_hidden')
        
        if not req_no:
            messages.error(request, "No Request Number provided!")
            return redirect('ri_picking')

        try:
            with transaction.atomic():
                inv_request = DeliveryRequest.objects.get(request_no=req_no)
                
                # Defense: Baka tapos na 'tong request na 'to
                if inv_request.status == 'Completed':
                    messages.warning(request, f"Request {req_no} has already been completed.")
                    return redirect('ri_picking')

                all_items_completed = True
                total_picked_items = 0

                # 1. I-loop lahat ng items sa request table
                for req_item in inv_request.items.all():
                    # Kunin yung tinype na 'Delivery Qty' sa UI natin
                    pick_qty_str = request.POST.get(f'pick_qty_{req_item.id}')
                    pick_rev_str = request.POST.get(f'pick_rev_{req_item.id}')
                    pick_price_str = request.POST.get(f'pick_price_{req_item.id}')
                    if pick_rev_str is not None:
                        req_item.revision = pick_rev_str.strip()

                    if pick_price_str is not None:
                        req_item.unit_price = float(pick_price_str)
                    
                    if pick_qty_str:
                        qty_to_pick = int(pick_qty_str)
                        
                        if qty_to_pick > 0:
                            # Defense: Baka sumobra yung pick sa remaining request
                            remaining_req = req_item.request_qty - req_item.delivered_qty
                            if qty_to_pick > remaining_req:
                                raise Exception(f"Cannot pick more than requested for {req_item.item_code}. Max allowed is {remaining_req}.")

                            # 🚀 2. FIFO INVENTORY DEDUCTION LOGIC
                            # Hahanapin natin ang mga Material Tags ng item na ito na may stock pa, 
                            # in-order by pinakaluma (First In, First Out)
                            available_tags = MaterialTag.objects.filter(
                                item_code=req_item.item_code, 
                                total_pcs__gt=0
                            ).order_by('arrival_date', 'id')

                            qty_needed = qty_to_pick
                            
                            for tag in available_tags:
                                if qty_needed <= 0:
                                    break # Tapos na kung nakuha na lahat ng kailangan
                                    
                                # Ilan ang pwede nating kunin sa Tag na ito?
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
                                    user=request.user,
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
        return redirect('ri_picking') # Palitan sa tamang URL name kung iba

    # GET Request
    locations = LocationMaster.objects.all().order_by('zone', 'location_code')
    return render(request, 'Inventory/receiving/RI_picking.html', {'locations': locations})

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

def get_picking_list(request):
    """Kinukuha ang Delivery Request items at ang current stock level nila."""
    req_no = request.GET.get('req_no', '').strip()
    
    del_request = DeliveryRequest.objects.filter(request_no=req_no).first()
    
    if not del_request:
        return JsonResponse({'success': False, 'error': f'Delivery Request {req_no} not found!'})

    if del_request.status == 'Completed':
        return JsonResponse({'success': False, 'error': f'Request {req_no} is already Completed!'})

    items_data = []
    
    for index, item in enumerate(del_request.items.all(), start=1): 
        remaining_qty = item.request_qty - item.delivered_qty
        
        if remaining_qty <= 0:
            continue
            
        from django.db.models import Sum
        from Inventory.models import Item

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
            
            # 🚀 FIX: Idinagdag natin ang Revision para maipasa sa UI!
            'revision': item.revision if item.revision else '---', 
            
            'request_qty': item.request_qty,
            'delivered_qty': item.delivered_qty,
            'remaining_qty': remaining_qty,
            'available_stock': total_available,
            'unit_price': float(current_price), 
        })

    if not items_data:
        return JsonResponse({'success': False, 'error': f'All items in {req_no} have already been delivered.'})

    return JsonResponse({
        'success': True,
        'req_no': del_request.request_no, 
        'delivery_place': del_request.delivery_place,
        'items': items_data
    })

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

                messages.success(request, f"Success! {tag.lot_no} moved from {old_loc} to {new_location.location_code}.")
                
        except MaterialTag.DoesNotExist:
            messages.error(request, "Error: Material Tag not found!")
        except Exception as e:
            messages.error(request, f"Error processing Stock Move: {str(e)}")
            
        return redirect('stock_move')

    # GET Request (Load page)
    # 🚀 FIX: Gumamit ng LocationMaster at inayos ang order_by
    locations = LocationMaster.objects.all().order_by('zone', 'location_code')
    return render(request, 'Inventory/inventory_request/stock_move.html', {'locations': locations})

def get_tag_info(request):
    """
    Ito ang sumasalo ng scan mula sa Stock Move, Stock Out, at Stock Correction.
    Nagbabalik ito ng JSON data papunta sa Javascript ng frontend.
    """
    lot_no_query = request.GET.get('lot_no', '').strip()

    if not lot_no_query:
        return JsonResponse({'success': False, 'error': 'No barcode scanned.'})

    try:
        # 1. Hanapin ang item gamit ang Lot Number
        tag = MaterialTag.objects.get(lot_no=lot_no_query)

        # 2. Ligtas na pagkuha ng Location (WALANG place_name o rack_bin dito!)
        current_loc = "Unassigned / No Location"
        if tag.location: # Kung may naka-link na LocationMaster
            try:
                # Gagamitin natin ang bagong field na location_code (e.g., RACK-A1)
                current_loc = tag.location.location_code
                
                # Optional: Kung may zone ka sa LocationMaster, pwede isama
                if hasattr(tag.location, 'zone') and tag.location.zone:
                    current_loc = f"{tag.location.location_code} | {tag.location.zone}"
            except Exception:
                current_loc = "Location Format Error"

        # 3. I-pack ang data at ibalik sa HTML
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
        # Kung hindi mahanap ang in-scan na barcode
        return JsonResponse({'success': False, 'error': f'Barcode {lot_no_query} not found in inventory.'})
    except Exception as e:
        # Para hindi mag-crash ang server kapag may ibang error
        return JsonResponse({'success': False, 'error': f'Server Error: {str(e)}'})

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

                # 2. Update Location (Kung may tinype sila at hindi kapareho ng dati)
                new_loc_str = old_loc # Default to old location string
                if new_loc_code and new_loc_code != old_loc:
                    new_location, _ = LocationMaster.objects.get_or_create(location_code=new_loc_code)
                    tag.location = new_location
                    new_loc_str = new_location.location_code

                tag.save()

                # 🚀 3. I-save sa StockLog (CRITICAL PARA SA AUDIT)
                notes = f"CORRECTION: Reason -> {reason}"
                if new_loc_str != old_loc:
                    notes += f" | Moved {old_loc} -> {new_loc_str}"

                StockLog.objects.create(
                    material_tag=tag,
                    action_type='CORR', # 'CORR' is defined in your StockLog models
                    old_qty=old_qty,
                    new_qty=new_qty,
                    change_qty=change_in_qty,
                    notes=notes,
                    user=request.user if request.user.is_authenticated else None
                )

                # 4. System Action Log
                log_system_action(
                    user=request.user, 
                    action='UPDATE', 
                    module='Inventory Control', 
                    description=f"Corrected Lot {tag.lot_no}. QTY: {old_qty}->{new_qty}. LOC: {old_loc}->{new_loc_str}. Reason: {reason}", 
                    request=request
                )

                alert_stock_correction(tag, old_qty, new_qty, reason, request.user)

                messages.success(request, f"Correction Saved! {tag.lot_no} updated. QTY: {old_qty} -> {new_qty} | LOC: {old_loc} -> {new_loc_str}.")
                return redirect('stock_correction')
                
        except MaterialTag.DoesNotExist:
             messages.error(request, "Error: Material Tag not found in database.")
        except Exception as e:
             messages.error(request, f"Error processing Stock Correction: {str(e)}")
             
        return redirect('stock_correction')

    return render(request, 'Inventory/inventory_request/stock_correction.html')

def stock_out_view(request):
    if request.method == 'POST':
        tag_id = request.POST.get('tag_id')
        qty_to_deduct_str = request.POST.get('qty_out')
        remarks = request.POST.get('remarks', 'Stock Out').strip()

        if not tag_id or not qty_to_deduct_str:
            messages.error(request, "System Error: Missing Tag ID or Quantity.")
            return redirect('stock_out')

        try:
            with transaction.atomic(): # 🚀 Use transaction to ensure data integrity
                tag = MaterialTag.objects.get(id=tag_id)
                deduct_val = int(qty_to_deduct_str)
                old_qty = tag.total_pcs

                if deduct_val <= 0:
                     messages.error(request, "Error: Deduction quantity must be greater than zero.")
                elif deduct_val > old_qty:
                    messages.error(request, f"Error: Cannot deduct {deduct_val} pcs. Only {old_qty} pcs remaining in Lot {tag.lot_no}.")
                else:
                    # 1. Update Quantity
                    tag.total_pcs -= deduct_val
                    new_qty = tag.total_pcs
                    tag.save()

                    # 🚀 2. CREATE STOCK LOG (Crucial for Audit Trail)
                    StockLog.objects.create(
                        material_tag=tag,
                        action_type='OUT', # 'OUT' is defined in your StockLog models
                        old_qty=old_qty,
                        new_qty=new_qty,
                        change_qty=-deduct_val, # Negative because it's a deduction
                        notes=f"ISSUANCE: {remarks}",
                        user=request.user if request.user.is_authenticated else None
                    )

                    # 3. System Action Log
                    log_system_action(
                        user=request.user, 
                        action='UPDATE', 
                        module='Inventory Issuance', 
                        description=f"Stock Out: Deducted {deduct_val} PCS from Lot {tag.lot_no}. Remarks: {remarks}", 
                        request=request
                    )
                    
                    check_and_alert_low_stock(tag)
                    
                    messages.success(request, f"Success! Deducted {deduct_val} pcs from {tag.lot_no}. Remaining: {new_qty} pcs.")
                    return redirect('stock_out') 
                
        except MaterialTag.DoesNotExist:
             messages.error(request, "Error: Material Tag not found in database.")
        except ValueError:
             messages.error(request, "Error: Invalid quantity entered.")
        except Exception as e:
            messages.error(request, f"Error processing Stock Out: {str(e)}")
            
        return redirect('stock_out')

    return render(request, 'Inventory/inventory_request/stock_out.html')

def stock_inquiry_view(request):
    # 1. Kunin ang lahat ng Physical Stocks (MaterialTags)
    # Gagamit tayo ng select_related para mabilis hugutin yung PO at Location data
    stocks = MaterialTag.objects.select_related('po_reference', 'po_reference__supplier', 'location').all().order_by('-arrival_date')

    # 2. Kunin ang mga isinubmit na Search Filters galing sa HTML Form
    inquiry_type = request.GET.get('inquiry_type')
    company = request.GET.get('company')
    item_code = request.GET.get('item_code')
    description = request.GET.get('description')
    lot_no = request.GET.get('lot_no')
    # (Pwede mong idagdag yung iba pang filters dito in the future)

    # 3. I-apply ang Filters kung may tinype/pinili ang user
    if inquiry_type == 'current':  
        stocks = stocks.filter(total_pcs__gt=0) 
    elif inquiry_type == 'out':
        stocks = stocks.filter(total_pcs__lte=0)
        
    if company:
        # Hahanapin sa loob ng PO -> Supplier -> Name
        stocks = stocks.filter(po_reference__supplier__name__icontains=company)
        
    if item_code:
        stocks = stocks.filter(item_code__icontains=item_code)
        
    if description:
        stocks = stocks.filter(description__icontains=description)
        
    if lot_no:
        stocks = stocks.filter(lot_no__icontains=lot_no)

    if request.GET.get('export_excel') == 'true':
        # 1. I-prepare natin yung data format na papasok sa Excel
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
                'PO No.': s.po_reference.po_no if s.po_reference else '',
                'Invoice No.': s.invoice_no if s.invoice_no else '',
                'Revision': s.revision if s.revision else '',
                'Receipt Date': s.arrival_date.strftime('%Y-%m-%d') if s.arrival_date else '',
                'Expiry Date': s.expiration_date.strftime('%Y-%m-%d') if s.expiration_date else '',
                'Quantity': s.total_pcs,
                'Unit': s.packing_type,
                'Unit Price': float(u_price),
            })

        # 2. I-convert yung data papuntang Pandas DataFrame
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="Stock_Masterlist_Export.xlsx"'

        # 4. Isulat yung DataFrame sa Excel file
        with pd.ExcelWriter(response, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Inventory Data')
            worksheet = writer.sheets['Inventory Data']
            for column_cells in worksheet.columns:
                length = max(len(str(cell.value)) for cell in column_cells)
                worksheet.column_dimensions[column_cells[0].column_letter].width = length + 2

        return response
    # ==========================================

    # Pag hindi Excel, ituloy lang sa normal na Pagination at rendering
    paginator = Paginator(stocks, 20) 
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    page_item_codes = [s.item_code for s in page_obj.object_list]
    page_item_prices = dict(Item.objects.filter(item_code__in=page_item_codes).values_list('item_code', 'unit_price'))

    context = {
        'page_obj': page_obj,
    }
    return render(request, 'Inventory/processing/stock_inquiry.html', context)

def stock_io_view(request, tag_id):
    # 1. Hanapin yung mismong Stock (Material Tag) na kinlick natin
    stock = get_object_or_404(MaterialTag, id=tag_id)
    
    # 2. Kunin lahat ng galaw (Logs) ng stock na 'to, mula pinakabago hanggang luma
    # Dahil may related_name='logs' ka sa models.py, madali lang natin itong tatawagin:
    history_logs = stock.logs.all().order_by('-timestamp')
    
    context = {
        'stock': stock,
        'history_logs': history_logs,
    }
    return render(request, 'Inventory/processing/stock_io_history.html', context)

def api_update_item_price(request):
    """ API para sa mabilisang pag-update ng Unit Price sa Stock Inquiry """
    if request.method == 'POST':
        item_code = request.POST.get('item_code', '').strip()
        new_price = request.POST.get('unit_price', 0)
        
        try:
            # Hanapin sa Masterlist at i-update
            item = Item.objects.get(item_code=item_code)
            item.unit_price = float(new_price)
            item.save()

            # (Optional) Pwede mo rin i-log dito kung gusto mo ma-track sino nagpalit ng presyo
            # log_system_action(user=request.user, action='UPDATE', module='Item Masterlist', description=f"Updated price of {item_code} to {new_price}")

            return JsonResponse({'success': True})
            
        except Item.DoesNotExist:
            return JsonResponse({'success': False, 'error': f'Item {item_code} not found in Masterlist.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
            
    return JsonResponse({'success': False, 'error': 'Invalid Request'})

def stock_item_inquiry_view(request):
    # 1. Kunin ang search query kung meron man
    search_query = request.GET.get('q', '').strip()
    
    # 2. I-Group ang database by Item Code at i-total ang quantity
    inventory = MaterialTag.objects.values('item_code', 'description').annotate(
        total_stock=Sum('total_pcs'),
        lot_count=Count('id')
    ).order_by('item_code')

    # 3. Kung may tinype sa search bar, i-filter natin
    if search_query:
        inventory = inventory.filter(
            Q(item_code__icontains=search_query) | 
            Q(description__icontains=search_query)
        )

    # 🚀 FIX: Kunin ang TOTOONG settings mula sa database
    sys_settings = SystemSetting.objects.first()
    # Default sa 50 kung walang laman ang database
    actual_threshold = sys_settings.low_stock_threshold if sys_settings else 50

    # 4. Pagination (20 items per page)
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
    # Tiyakin na tama ang pangalan ng HTML file mo dito
    return render(request, 'Inventory/processing/stock_item_inquiry.html', context)

def stock_history_view(request):
    # 1. Kunin ang lahat ng movement logs, pinakabago ang nasa itaas
    # Gagamit tayo ng select_related para mabilis makuha yung Item Code at Lot No galing sa MaterialTag
    logs = StockLog.objects.select_related('material_tag', 'user').all().order_by('-timestamp')

    # 2. Kunin ang mga filters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    action_type = request.GET.get('action_type')
    item_code = request.GET.get('item_code')
    lot_no = request.GET.get('lot_no')

    # 3. I-apply ang Filters
    if date_from:
        logs = logs.filter(timestamp__date__gte=date_from) # gte = Greater Than or Equal
    if date_to:
        logs = logs.filter(timestamp__date__lte=date_to)   # lte = Less Than or Equal
    if action_type:
        logs = logs.filter(action_type=action_type)
    if item_code:
        logs = logs.filter(material_tag__item_code__icontains=item_code)
    if lot_no:
        logs = logs.filter(material_tag__lot_no__icontains=lot_no)

    # 4. Pagination (20 rows per page)
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj,
    }
    return render(request, 'Inventory/processing/stock_history.html', context)

def request_inquiry_view(request):
    # 1. Kunin lahat ng requests (Assuming may MaterialRequest model ka)
    # Kung wala pa, gagana pa rin ang page pero walang data na lalabas.
    requests_data = DeliveryRequest.objects.annotate(
        item_count=Count('items'),
        total_qty=Sum('items__request_qty')
    ).order_by('-request_date', '-request_no')
        
    # 2. Kunin ang mga filters
    req_no = request.GET.get('req_no')
    status = request.GET.get('status')
    department = request.GET.get('department')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')

    # 3. I-apply ang Filters (Kung may model na)
    if req_no:
        requests_data = requests_data.filter(request_no__icontains=req_no)
    if status:
        requests_data = requests_data.filter(status=status)
    if department:
        # Note: 'receiving_place' ang ginamit nating equivalent ng department sa form
        requests_data = requests_data.filter(receiving_place__icontains=department)
    if date_from:
        requests_data = requests_data.filter(request_date__gte=date_from)
    if date_to:
        requests_data = requests_data.filter(request_date__lte=date_to)

    # 4. Pagination (20 items per page)
    paginator = Paginator(requests_data, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'requests': page_obj,
    }
    return render(request, 'Inventory/processing/request_inquiry.html', context)

def inquiry_settings_view(request):
    # 1. Kunin ang nag-iisang SystemSetting record. Kung wala, gagawa siya ng bago.
    # Gagamit tayo ng get_or_create para kahit fresh yung database, hindi mag-e-error.
    system_settings, created = SystemSetting.objects.get_or_create(id=1)

    if request.method == 'POST':
        # 2. Kunin ang mga bagong values galing sa HTML Form
        low_stock_limit = request.POST.get('low_stock_limit')
        items_per_page = request.POST.get('items_per_page')
        email_alerts = request.POST.get('email_alerts') # Checkbox ito, returns 'on' if checked
        
        # 3. I-update ang record sa database
        try:
            # Update Low Stock Threshold
            if low_stock_limit and low_stock_limit.isdigit():
                system_settings.low_stock_threshold = int(low_stock_limit)
            
            # Update Email Alerts
            system_settings.enable_email_alerts = True if email_alerts == 'on' else False
            
            # I-save
            system_settings.save()
            
            # 4. Optional: I-save sa Session ang "Items Per Page" para per-user setting siya
            # Mas maganda itong nasa session lang para hindi nakakaapekto sa ibang users.
            if items_per_page and items_per_page.isdigit():
                request.session['items_per_page'] = int(items_per_page)

            # 5. Log the action para sa Audit Trail
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

    # GET Request: Ipakita ang form gamit ang TOTOONG data
    context = {
        'low_stock_limit': system_settings.low_stock_threshold,
        'email_alerts_enabled': system_settings.enable_email_alerts,
        
        # Kunin sa session kung meron, kung wala, default ay 50
        'items_per_page': request.session.get('items_per_page', 50), 
    }
    return render(request, 'Inventory/processing/inquiry_settings.html', context)

def shipment_import_view(request):
    if request.method == 'POST' and request.FILES.get('excel_file'):
        excel_file = request.FILES['excel_file']
        
        try:
            # 1. Basahin ang Excel
            df = pd.read_excel(excel_file)
            
            # 2. 🚀 BULLETPROOF HEADERS: Gawing uppercase at palitan ang spaces ng underscore
            df.columns = [str(c).strip().upper().replace(' ', '_') for c in df.columns]

            success_count = 0
            for index, row in df.iterrows():
                # 3. 🚀 FLEXIBLE MAPPING: Hahanapin natin pareho yung tinype mo sa HTML at sa Python
                ship_no = row.get('SHIPMENT_ID') if pd.notna(row.get('SHIPMENT_ID')) else row.get('SHIPMENT_NO')
                
                if pd.isna(ship_no) or not str(ship_no).strip():
                    continue # I-skip ang blank rows
                
                ship_no = str(ship_no).strip()
                item_code = str(row.get('ITEM_CODE', '')).strip()
                
                # Handling Quantity (Fallback to 0 if empty)
                qty_raw = row.get('QTY') if pd.notna(row.get('QTY')) else row.get('QUANTITY')
                qty = int(qty_raw) if pd.notna(qty_raw) else 0
                
                # Handling Date (Fallback to today if empty)
                date_raw = row.get('DELIVERY_DATE') if pd.notna(row.get('DELIVERY_DATE')) else row.get('DATE')
                sched_date = pd.to_datetime(date_raw).date() if pd.notna(date_raw) else timezone.now().date()

                # Optional Fields
                inv_no = str(row.get('INVOICE_NO', '')).strip() if pd.notna(row.get('INVOICE_NO')) else None
                trans = str(row.get('TRANSPORT', '')).strip() if pd.notna(row.get('TRANSPORT')) else None
                
                # Destination (Kailangan may laman kasi required sa models.py mo!)
                dest = str(row.get('DESTINATION', 'Default Warehouse')).strip()

                # Customer Logic
                customer_obj = None
                cust_raw = row.get('CUSTOMER')
                if pd.notna(cust_raw) and str(cust_raw).strip():
                    customer_name = str(cust_raw).strip()
                    customer_obj, _ = Contact.objects.get_or_create(
                        name=customer_name, 
                        defaults={'contact_type': 'Customer'}
                    )

                # 4. Save to Database
                ShipmentSchedule.objects.update_or_create(
                    shipment_no=ship_no,
                    defaults={
                        'item_code': item_code,
                        'destination': dest,
                        'quantity': qty,
                        'schedule_date': sched_date,
                        'customer': customer_obj,       
                        'invoice_no': inv_no,           
                        'transport': trans,             
                        'status': 'Pending' # Default status pagka-import
                    }
                )
                success_count += 1

            # I-log ang action
            log_system_action(
                user=request.user, 
                action='CREATE', 
                module='Shipment Schedule', 
                description=f"Bulk imported/updated {success_count} shipment schedules via Excel.", 
                request=request
            )
                
            messages.success(request, f"Success! {success_count} shipment schedules imported/updated.")
            
        except Exception as e:
            # I-print sa terminal yung error para madaling i-debug kung may maling column
            print("=========================================")
            print(f"EXCEL IMPORT ERROR: {str(e)}")
            print("Columns detected:", df.columns.tolist() if 'df' in locals() else 'None')
            print("=========================================")
            messages.error(request, f"Import Error: Please make sure headers match exactly. System read: {str(e)}")
            
        return redirect('shipment_import')

    return render(request, 'Inventory/inquiry/shipment_import.html')

# 2. SHIPMENT INQUIRY: Ang taga-lista ng parating na shipments
def shipment_inquiry_view(request):
    # 1. Kunin lahat ng shipments (Pinakabago sa itaas)
    shipments = ShipmentSchedule.objects.all().order_by('-schedule_date')
    
    # 2. Kunin lahat ng 'Customer' galing sa Contact table para sa Dropdown sa UI
    customers_list = Contact.objects.filter(contact_type='Customer')

    # 3. Kunin ang mga isinubmit na Search Filters galing sa HTML Form
    customer_id = request.GET.get('customer')
    date_in = request.GET.get('date_in')
    date_out = request.GET.get('date_out')
    transport = request.GET.get('transport')
    item_code = request.GET.get('item_code')
    invoice_no = request.GET.get('invoice_no')
    status = request.GET.get('status')

    # 4. I-apply ang Filters kung may tinype/pinili ang user
    if customer_id:
        shipments = shipments.filter(customer_id=customer_id)
        
    if date_in and date_out:
        shipments = shipments.filter(schedule_date__range=[date_in, date_out])
    elif date_in: # Kung start date lang ang nilagay
        shipments = shipments.filter(schedule_date__gte=date_in)
        
    if transport:
        shipments = shipments.filter(transport=transport)
        
    if item_code:
        shipments = shipments.filter(item_code__icontains=item_code)
        
    if invoice_no:
        shipments = shipments.filter(invoice_no__icontains=invoice_no)
        
    if status:
        shipments = shipments.filter(status=status)

    # 5. Pagination (20 rows per page)
    paginator = Paginator(shipments, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'shipments': page_obj,
        'customers_list': customers_list, # Ipapasa natin ito sa HTML
    }
    return render(request, 'Inventory/inquiry/shipment_inquiry.html', context)

# 3. SHIPPING CONFIRMATION: Ang taga-release ng truck
def shipping_confirmation_view(request):
    # GET: Kunin lang yung mga hindi pa 'Completed' o 'Received'
    pending_shipments = ShipmentSchedule.objects.filter(
        status__in=['Pending', 'Shipped', 'Determined', 'In Transit']
    ).order_by('schedule_date')

    if request.method == 'POST':
        shipment_id = request.POST.get('shipment_id')
        actual_qty = request.POST.get('actual_qty')
        lot_no = request.POST.get('lot_no').strip()
        expiry_date = request.POST.get('expiry_date')
        remarks = request.POST.get('remarks')

        try:
            # 1. Hanapin ang Shipment
            shipment = ShipmentSchedule.objects.get(id=shipment_id)

            # 2. I-check kung may kaparehas nang Lot Number sa database (bawal ma-doble)
            if MaterialTag.objects.filter(lot_no=lot_no).exists():
                messages.error(request, f"Error: Lot Number '{lot_no}' already exists in the inventory!")
                return redirect('shipping_confirmation')

            # 3. GUMAWA NG BAGONG MATERIAL TAG (Papasok na sa Inventory!)
            MaterialTag.objects.create(
                item_code=shipment.item_code,
                description=f"Received from Shipment {shipment.shipment_no}",
                lot_no=lot_no,
                total_pcs=int(actual_qty),
                expiration_date=expiry_date if expiry_date else None,
                arrival_date=timezone.now().date(),
                inspection_status='Pending', # Pwedeng i-QC mamaya
                remarks=remarks
            )

            # 4. I-update ang status ng Shipment para mawala na sa listahan
            shipment.status = 'Completed'
            shipment.save()

            log_system_action(
                user=request.user, 
                action='UPDATE', 
                module='Shipping Confirmation', 
                description=f"Received Shipment {shipment.shipment_no} and generated Lot {lot_no}.", 
                request=request
            )

            messages.success(request, f"SUCCESS! Shipment {shipment.shipment_no} received. Material Tag (Lot: {lot_no}) generated.")
            return redirect('shipping_confirmation')

        except ShipmentSchedule.DoesNotExist:
            messages.error(request, "Shipment record not found.")
        except Exception as e:
            messages.error(request, f"Error during confirmation: {str(e)}")

    context = {
        'shipments': pending_shipments
    }
    return render(request, 'Inventory/inquiry/shipping_confirmation.html', context)


@login_required
def analytics_view(request):
    try:
        settings = SystemSetting.objects.first()
        threshold = settings.low_stock_threshold if settings else 50
    except Exception:
        threshold = 50

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

    # 2. STOCK HEALTH
    inventory_grouped = MaterialTag.objects.values('item_code', 'description').annotate(
        total_stock=Sum('total_pcs')
    )
    low_stock_items = [item for item in inventory_grouped if item['total_stock'] < threshold]
    critical_count = len(low_stock_items)
    healthy_count = len([item for item in inventory_grouped if item['total_stock'] >= threshold])

    # 🚀 3. INVENTORY FLOW (LAST 7 DAYS) - PARA SA LINE CHART
    today = timezone.now().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    
    flow_dates = [d.strftime('%b %d') for d in last_7_days]
    flow_in = []
    flow_out = []

    for d in last_7_days:
        day_in = StockLog.objects.filter(timestamp__date=d, action_type__in=['IN', 'REG']).aggregate(Sum('change_qty'))['change_qty__sum'] or 0
        day_out_raw = StockLog.objects.filter(timestamp__date=d, action_type='OUT').aggregate(Sum('change_qty'))['change_qty__sum'] or 0
        flow_in.append(day_in)
        flow_out.append(abs(day_out_raw)) # Gawing positive para sa chart

    # 4. RECENT ACTIVITY FEED
    recent_logs = StockLog.objects.select_related('user', 'material_tag').order_by('-timestamp')[:6]

    # 🚀 5. PER WAREHOUSE UTILIZATION - PARA SA HORIZONTAL BAR CHART
    warehouses = LocationMaster.objects.values('warehouse').annotate(
        total_cap=Sum('capacity')
    ).exclude(warehouse__exact='')

    wh_labels = []
    wh_util_data = []

    for wh in warehouses:
        wh_name = wh['warehouse']
        t_cap = wh['total_cap'] or 1 # Iwas divide-by-zero
        
        # Ilan ang laman ng specific warehouse na ito?
        used = MaterialTag.objects.filter(location__warehouse=wh_name).aggregate(Sum('total_pcs'))['total_pcs__sum'] or 0
        
        # Compute percentage (Ila-lock sa 100% max para hindi masira ang chart kung may overstock)
        used_capped = min(used, t_cap)
        pct = round((used_capped / t_cap) * 100, 1)

        wh_labels.append(wh_name)
        wh_util_data.append(pct)

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

    # 7. CONTEXT
    context = {
        'total_skus': total_skus,
        'pending_shipments': pending_shipments,
        'total_pcs': total_pcs,
        'total_inventory_value': total_inventory_value,
        'critical_count': critical_count,
        'low_stock_items': low_stock_items[:5], 
        'recent_logs': recent_logs,
        'chart_health_data': json.dumps([healthy_count, critical_count]), 
        
        # Bagong Chart Data:
        'flow_dates': json.dumps(flow_dates),
        'flow_in': json.dumps(flow_in),
        'flow_out': json.dumps(flow_out),
        'wh_labels': json.dumps(wh_labels),
        'wh_util_data': json.dumps(wh_util_data),
        
        'top_items': top_items,
        'threshold': threshold
    }
    
    return render(request, 'Inventory/analytics_board.html', context)

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
def email_master_view(request):
    # Kukunin lahat ng naka-setup na rules sa database
    routes = EmailRoute.objects.all().order_by('event_name')
    return render(request, 'Inventory/master/email_master.html', {'routes': routes})

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

def send_shipping_notification(order_no, customer_email, courier_name, tracking_number):
    if not customer_email:
        return False 
        
    try:
        subject = f"Your Order {order_no} has been Shipped!"
        context = {
            'order_no': order_no,
            'courier_name': courier_name,
            'tracking_number': tracking_number
        }
        
        html_message = render_to_string('Inventory/emails/shipping_notification_email.html', context)
        plain_message = strip_tags(html_message)
        
        send_mail(subject, plain_message, django_settings.DEFAULT_FROM_EMAIL, [customer_email], html_message=html_message, fail_silently=False)
        return True
    except Exception as e:
        print(f"Failed to send shipping email to customer: {str(e)}")
        return False

def alert_stock_correction(tag, old_qty, new_qty, reason, user):
    try:
        route = EmailRoute.objects.get(event_name='STOCK_CORRECTION', is_active=True)
        target_emails = route.get_email_list()

        if target_emails:
            subject = f"📝 AUDIT ALERT: Stock Correction on Lot {tag.lot_no}"
            
            difference = new_qty - old_qty
            diff_str = f"+{difference}" if difference > 0 else str(difference)

            context = {
                'item_code': tag.item_code,
                'lot_no': tag.lot_no,
                'old_qty': old_qty,
                'new_qty': new_qty,
                'difference': diff_str,
                'reason': reason,
                'username': user.username if user else 'SYSTEM'
            }

            html_message = render_to_string('Inventory/emails/stock_correction_email.html', context)
            plain_message = strip_tags(html_message)

            send_mail(
                subject, 
                plain_message, 
                django_settings.DEFAULT_FROM_EMAIL, 
                target_emails, 
                html_message=html_message, 
                fail_silently=False
            )
            print(f"Stock correction email sent for Lot {tag.lot_no}")
            
    except EmailRoute.DoesNotExist:
        print("Notice: No email route setup for STOCK_CORRECTION.")
    except Exception as e:
        print(f"Error sending correction alert: {str(e)}")

def alert_new_delivery_request(delivery_request):
    try:
        route = EmailRoute.objects.get(event_name='NEW_DELIVERY_REQ', is_active=True)
        target_emails = route.get_email_list()

        if target_emails:
            subject = f"🚚 NEW REQUEST: Movement Slip {delivery_request.request_no}"
            
            # Bilangin kung ilang items ang nasa request
            item_count = delivery_request.items.count()

            context = {
                'req_no': delivery_request.request_no,
                'destination': delivery_request.receiving_place,
                'requestor': delivery_request.requestor or 'Not specified',
                'item_count': item_count,
                'remarks': delivery_request.remarks
            }

            html_message = render_to_string('Inventory/emails/new_delivery_request_email.html', context)
            plain_message = strip_tags(html_message)

            send_mail(
                subject, 
                plain_message, 
                django_settings.DEFAULT_FROM_EMAIL, 
                target_emails, 
                html_message=html_message, 
                fail_silently=False
            )
            print(f"Delivery request email sent for {delivery_request.request_no}")
            
    except EmailRoute.DoesNotExist:
        print("Notice: No email route setup for NEW_DELIVERY_REQ.")
    except Exception as e:
        print(f"Error sending delivery request alert: {str(e)}")

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
    all_items = Item.objects.all()
    low_stock_items = []
    
    print("\n--- RUNNING LOW STOCK DEBUG ---") # Para makita natin sa terminal
    
    for item in all_items:
        safe_item_code = str(item.item_code).strip()
        
        # 🚀 FIX: Gagamit tayo ng .annotate(clean_code=Trim('item_code')) 
        # para linisin ang invisible spaces sa mismong Database bago mag-hanap!
        total_stock = MaterialTag.objects.annotate(
            clean_code=Trim('item_code')
        ).filter(
            clean_code__iexact=safe_item_code
        ).aggregate(Sum('total_pcs'))['total_pcs__sum'] or 0
        
        # Ipi-print natin sa terminal para makita mo yung totoong bilang per item
        print(f"Checking {safe_item_code}: Found {total_stock} PCS")
        
        if total_stock < 50:
            low_stock_items.append({
                'item_code': safe_item_code,
                'description': item.description,
                'current_stock': total_stock,
                'total_stock': total_stock,
                'threshold': 50
            })
            
    print("-------------------------------\n")
            
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
                    from_email=settings.DEFAULT_FROM_EMAIL, # Siguraduhing tama itong settings variable mo
                    recipient_list=target_emails,
                    html_message=html_msg,
                    fail_silently=False
                )
        except Exception as e:
            print(f"Error sending Low Stock email: {str(e)}")
            
    return len(low_stock_items)

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
        send_test("New User Registered", "new_user_email.html", {
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

        # Success!
        messages.success(request, f"MASSIVE SUCCESS! 7 Test Emails with HTML Designs were sent to: {', '.join(target_emails)}. Check your Inbox!")

    except EmailRoute.DoesNotExist:
        messages.error(request, "Test Failed: Please setup the 'TEST_ALERT' event in your Email Routes first.")
    except Exception as e:
        messages.error(request, f"SMTP/Connection Error: {str(e)}")

    return redirect('email_master')