from django.urls import reverse
import datetime 
from django.utils import timezone
from datetime import timedelta
from django.db.models import Sum
from django.core.mail import EmailMultiAlternatives, send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User
from .models import (
    SystemAuditLog, 
    SystemNotification, 
    EmailRoute, 
    MaterialTag, 
    PurchaseOrder, 
    DeliveryRequest,
    CustomerOrder,
    NotificationSubscription,
    SystemSetting,
    Item,
    StockLog
)

# ==========================================
# SYSTEM & AUDIT LOGS
# ==========================================

def log_system_action(user, action, module, description, request=None):
    """ Saves an Audit Log with IP tracking. """
    ip = None
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

    SystemAuditLog.objects.create(
        user=user if user and user.is_authenticated else None,
        action=action.upper(), 
        module=module.upper(),
        description=description,
        ip_address=ip
    )

# ==========================================
# WEB / IN-APP NOTIFICATIONS CORE
# ==========================================

def send_in_app_notification(user, title, message, level='INFO', link=None):
    """ Sends direct notification to a specific user. """
    if user and user.is_active:
        SystemNotification.objects.create(
            user=user,
            title=title,
            message=message,
            level=level.upper(),
            link=link
        )

def notify_admins(title, message, link=None):
    """ Broadcast: Nagpapadala ng alert sa LAHAT ng Admins/Superusers """
    admins = User.objects.filter(is_superuser=True)
    for admin in admins:
        send_in_app_notification(admin, title, message, level='WARNING', link=link)

def notify_web_users_for_event(event_name, title, message, level='INFO', link=None):
    """
    Hahanapin nito lahat ng users na may check ang "Web App" para sa specific event,
    tapos gagawan sila ng SystemNotification sa database.
    """
    try:
        route = EmailRoute.objects.get(event_name=event_name, is_active=True)
        web_subs = NotificationSubscription.objects.filter(route=route, notify_web=True)
        
        for sub in web_subs:
            send_in_app_notification(
                user=sub.user, 
                title=title, 
                message=message, 
                level=level, 
                link=link
            )
    except EmailRoute.DoesNotExist:
        pass
    except Exception as e:
        print(f"Error in web notification dispatcher: {e}")


# ==========================================
# EMAIL & HYBRID TRIGGERS (WEB + EMAIL)
# ==========================================

def send_shipping_notification(order_no, customer_email, courier_name, tracking_number=""):
    """ Customer Email Only (No internal web alert) """
    if not customer_email: return False
    subject = f"Shipping Update: Order #{order_no} is on its way!"
    tracking_info = f"\nTracking Number: {tracking_number}" if tracking_number else ""
    message = f"Hello,\n\nGood news! Your order #{order_no} has been packed and handed over to our logistics partner.\n\nCourier: {courier_name} {tracking_info}\n\nPlease expect your delivery soon. Thank you!\n\nBest regards,\nASIA Integrated Machine Inc."
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [customer_email], fail_silently=False)
        return True
    except Exception as e:
        print(f"Failed to send shipping email: {e}")
        return False

def send_order_acknowledgement(order_no, customer_email, total_amount, item_count):
    """ Customer Email Only """
    if not customer_email: return False
    subject = f"Order Confirmation: #{order_no} Received"
    message = f"Hello,\n\nThank you for your order! We have received your purchase request.\n\nOrder Summary:\n- Order No: {order_no}\n- Total Items: {item_count}\n- Grand Total: PHP {total_amount:,.2f}\n\nOur warehouse team will now begin processing your order. You will receive another update once it is ready for shipping.\n\nBest regards,\nASIA Integrated Corp."
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [customer_email], fail_silently=False)
        return True
    except Exception as e:
        print(f"Failed to send acknowledgment for Order {order_no}: {e}")
        return False

def send_new_material_request_alert(request_obj):
    print(f"--- 🚀 HYBRID TRIGGER FOR REQ: {request_obj.request_no} ---")
    
    # 🚀 DYNAMIC LINK: Mapupunta sa Order Picking
    action_link = reverse('ri_picking')
    
    notify_web_users_for_event(
        event_name='NEW_MATERIAL_REQ',
        title="New Material Request",
        message=f"Movement slip {request_obj.request_no} submitted for {request_obj.receiving_place}.",
        level='INFO',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='NEW_MATERIAL_REQ', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"WMS Alert: New Material Request ({request_obj.request_no})"
            html_content = render_to_string('Inventory/emails/new_material_request.html', {'req': request_obj})
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_assembly_completed_alert(machine_obj):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR ASSEMBLY: {machine_obj.machine_code} ---")
    
    # 🚀 DYNAMIC LINK: Mapupunta sa Machine Details
    action_link = reverse('machine_detail', args=[machine_obj.id])
    
    notify_web_users_for_event(
        event_name='ASSEMBLY_COMPLETED',
        title="Assembly Completed",
        message=f"Production for Machine {machine_obj.machine_code} is fully complete.",
        level='SUCCESS',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='ASSEMBLY_COMPLETED', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"Production Alert: Machine Ready ({machine_obj.machine_code})"
            html_content = render_to_string('Inventory/emails/assembly_completed.html', {'machine': machine_obj})
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_stock_move_alert(tag, old_loc, new_loc, user):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR STOCK MOVE: {tag.lot_no} ---")
    
    # 🚀 DYNAMIC LINK: Mapupunta sa Stock Inquiry
    action_link = reverse('stock_inquiry')
    
    notify_web_users_for_event(
        event_name='STOCK_MOVE',
        title="Stock Moved",
        message=f"Lot {tag.lot_no} was moved to {new_loc} by {user.username}.",
        level='INFO',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_MOVE', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"Inventory Alert: Stock Moved ({tag.lot_no})"
            html_content = render_to_string('Inventory/emails/stock_move_email.html', {'tag': tag, 'old_loc': old_loc, 'new_loc': new_loc, 'user': user})
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_stock_correction_alert(tag, old_qty, new_qty, reason, user):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR STOCK CORRECTION: {tag.lot_no} ---")
    
    # 🚀 DYNAMIC LINK: Mapupunta sa Stock History ng specific Tag
    action_link = reverse('stock_io_history', args=[tag.id])
    
    notify_web_users_for_event(
        event_name='STOCK_CORRECTION',
        title="Stock Override",
        message=f"Lot {tag.lot_no} updated from {old_qty} to {new_qty}. Reason: {reason}",
        level='WARNING',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_CORRECTION', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"CRITICAL: Stock Override Alert ({tag.lot_no})"
            context = {'lot_no': tag.lot_no, 'item_code': tag.item_code, 'old_qty': old_qty, 'new_qty': new_qty, 'reason': reason, 'user': user.username if user else "System"}
            html_content = render_to_string('Inventory/emails/stock_correction_email.html', context)
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_stock_out_alert(tag, deduct_qty, remaining_qty, remarks, user):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR STOCK OUT: {tag.lot_no} ---")
    
    action_link = reverse('stock_io_history', args=[tag.id])
    
    notify_web_users_for_event(
        event_name='STOCK_OUT',
        title="Stock Deducted",
        message=f"{deduct_qty} items issued from Lot {tag.lot_no}. Remaining: {remaining_qty}.",
        level='INFO',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_OUT', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"Inventory Alert: Stock Out ({tag.lot_no})"
            context = {'lot_no': tag.lot_no, 'item_code': tag.item_code, 'deduct_qty': deduct_qty, 'remaining_qty': remaining_qty, 'remarks': remarks, 'user': user.username if user else "System"}
            html_content = render_to_string('Inventory/emails/stock_out_email.html', context)
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_po_approval_alert(main_po_no, batch_id, po_count, user):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR PO APPROVAL: {main_po_no} ---")
    
    # 🚀 DYNAMIC LINK: Mapupunta sa Approve PO
    action_link = reverse('approve_po')
    
    notify_web_users_for_event(
        event_name='PO_APPROVAL',
        title="PO Approval Required",
        message=f"Batch {batch_id} ({po_count} orders) awaits your approval.",
        level='WARNING',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='PO_APPROVAL', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"Action Required: PO Approval for {main_po_no}"
            context = {'main_po_no': main_po_no, 'batch_id': batch_id, 'po_count': po_count, 'user': user.username if user else "System"}
            html_content = render_to_string('Inventory/emails/po_alert_email.html', context)
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_po_approved_notification(batch_id, po_count, creator_email, creator_name, approver_name):
    # This specifically goes to the PO Creator via Email
    subject = f"WMS Alert: Your PO Batch {batch_id} is Approved!"
    context = {'batch_id': batch_id, 'po_count': po_count, 'creator_name': creator_name, 'approver_name': approver_name}
    try:
        html_content = render_to_string('Inventory/emails/po_approved_email.html', context)
        msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, [creator_email])
        msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False) 
    except Exception:
        pass

def alert_new_delivery_request(request_obj):
    print(f"\n--- 🚀 HYBRID TRIGGER FOR NEW DELIVERY REQ: {request_obj.request_no} ---")
    
    action_link = reverse('ri_picking')
    
    notify_web_users_for_event(
        event_name='NEW_DELIVERY_REQ',
        title="New Movement Slip",
        message=f"Delivery Request {request_obj.request_no} created for {request_obj.receiving_place}.",
        level='INFO',
        link=action_link
    )
    
    try:
        route = EmailRoute.objects.get(event_name='NEW_DELIVERY_REQ', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"Logistics Alert: New Movement Slip ({request_obj.request_no})"
            context = {'request_no': request_obj.request_no, 'client_name': request_obj.receiving_place, 'delivery_date': request_obj.delivery_date, 'item_count': request_obj.items.count() if hasattr(request_obj, 'items') else 0, 'reason': request_obj.reason, 'user': "System User"}
            html_content = render_to_string('Inventory/emails/delivery_request_email.html', context)
            msg = EmailMultiAlternatives(subject, strip_tags(html_content), settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
    except Exception as e:
        print(f"Email Error: {e}")

def send_security_alert_email(username, ip, count):
    action_link = reverse('system_audit_logs')
    notify_web_users_for_event(
        event_name='SECURITY_ALERT',
        title="Security Alert",
        message=f"{count} failed login attempts for account '{username}' from IP: {ip}.",
        level='ERROR',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='SECURITY_ALERT', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"⚠️ SECURITY WARNING: Multiple Failed Logins for [{username}]"
            context = {'username': username, 'ip': ip, 'count': count}
            html_message = render_to_string('Inventory/emails/security_alert_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass

def send_qc_rejection_alert(instance):
    action_link = reverse('stock_io_history', args=[instance.id])
    notify_web_users_for_event(
        event_name='QC_FAILED',
        title="QC Rejected",
        message=f"Lot {instance.lot_no} ({instance.item_code}) failed quality inspection.",
        level='ERROR',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='QC_FAILED', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"🚨 URGENT QC ALERT: Material Rejected - Lot: {instance.lot_no}"
            context = {'item_code': instance.item_code, 'description': instance.description, 'lot_no': instance.lot_no, 'qty': instance.total_pcs, 'uom': instance.packing_type, 'remarks': instance.remarks or 'No remarks provided by inspector.'}
            html_message = render_to_string('Inventory/emails/qc_failed_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass

def send_late_delivery_alert(po_data, total_count):
    action_link = reverse('shipment_inquiry')
    notify_web_users_for_event(
        event_name='LATE_DELIVERY',
        title="Late Delivery Alert",
        message=f"{total_count} Purchase Orders are currently overdue.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='LATE_DELIVERY', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"⚠️ LOGISTICS ALERT: {total_count} Overdue Purchase Orders"
            context = {'pos': po_data, 'total_count': total_count}
            html_message = render_to_string('Inventory/emails/late_delivery_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass

def send_po_status_update_email(po, manager_user):
    recipient_email = po.created_by.email if po.created_by and po.created_by.email else None
    if not recipient_email: return
    try:
        subject = f"P.O. UPDATE: {po.po_no} is {po.ordering_status}"
        context = {'status': po.ordering_status, 'po_no': po.po_no, 'supplier': po.supplier.name if po.supplier else 'N/A', 'manager': manager_user.username if manager_user else 'System Admin'}
        html_message = render_to_string('Inventory/emails/po_status_update_email.html', context)
        send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, [recipient_email], html_message=html_message, fail_silently=False)
    except Exception:
        pass

def send_low_stock_email_alert(low_stock_items):
    action_link = reverse('stock_item_inquiry')
    notify_web_users_for_event(
        event_name='LOW_STOCK',
        title="Low Stock Alert",
        message=f"{len(low_stock_items)} items have fallen below the critical threshold.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='LOW_STOCK', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            context = {'items': low_stock_items, 'total_count': len(low_stock_items)}
            html_msg = render_to_string('Inventory/emails/low_stock_email.html', context)
            send_mail(subject=f"⚠️ WMS ALERT: {len(low_stock_items)} Low Stock Items Detected", message="Low stock items detected.", from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=target_emails, html_message=html_msg, fail_silently=False)
    except Exception:
        pass

def scan_pending_qc():
    pending_tags = MaterialTag.objects.filter(inspection_status='Pending')
    if not pending_tags.exists(): return 0
    
    action_link = reverse('stock_inquiry')
    notify_web_users_for_event(
        event_name='QC_PENDING',
        title="QC Reminder",
        message=f"{pending_tags.count()} material tags are waiting for quality inspection.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='QC_PENDING', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"⚠️ QA REMINDER: {pending_tags.count()} Items Pending Inspection"
            message = f"Hello QA Team,\n\nYou have {pending_tags.count()} material tags waiting for quality inspection. Please check the system to process them."
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, target_emails, fail_silently=False)
    except Exception:
        pass
    return pending_tags.count()

def scan_aging_requests():
    three_days_ago = timezone.now().date() - timedelta(days=3)
    aging_reqs = DeliveryRequest.objects.filter(status__in=['Pending', 'Processing'], request_date__lte=three_days_ago).order_by('request_date')
    if not aging_reqs.exists(): return 0
    
    action_link = reverse('request_inquiry')
    notify_web_users_for_event(
        event_name='AGING_REQUESTS',
        title="Aging Requests",
        message=f"{aging_reqs.count()} material requests have been pending for over 3 days.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='AGING_REQUESTS', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"⏳ WAREHOUSE ALERT: {aging_reqs.count()} Aging Material Requests"
            context = {'count': aging_reqs.count(), 'requests': aging_reqs[:10]}
            html_message = render_to_string('Inventory/emails/aging_requests_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass
    return aging_reqs.count()

def scan_pending_pos():
    pending_pos = PurchaseOrder.objects.filter(ordering_status='Pending Approval').order_by('order_date')
    if not pending_pos.exists(): return 0
    
    action_link = reverse('approve_po')
    notify_web_users_for_event(
        event_name='PO_APPROVAL',
        title="Pending POs",
        message=f"{pending_pos.count()} Purchase Orders are waiting for Manager Approval.",
        level='INFO',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='PO_APPROVAL', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"🔔 MANAGER REMINDER: {pending_pos.count()} Purchase Orders Awaiting Approval"
            context = {'count': pending_pos.count(), 'pos': pending_pos[:10]}
            html_message = render_to_string('Inventory/emails/pending_pos_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass
    return pending_pos.count()

def scan_dead_stock():
    six_months_ago = timezone.now().date() - timedelta(days=180)
    dead_stocks = MaterialTag.objects.filter(total_pcs__gt=0, arrival_date__lte=six_months_ago).order_by('arrival_date')
    if not dead_stocks.exists(): return 0
    
    action_link = reverse('analytics_board')
    notify_web_users_for_event(
        event_name='DEAD_STOCK',
        title="Dead Stock Alert",
        message=f"{dead_stocks.count()} lots have not moved in over 6 months.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='DEAD_STOCK', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            subject = f"🕸️ FINANCE ALERT: {dead_stocks.count()} Slow-Moving / Dead Stock Lots Detected"
            context = {'count': dead_stocks.count(), 'stocks': dead_stocks[:10], 'months': 6}
            html_message = render_to_string('Inventory/emails/dead_stock_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass
    return dead_stocks.count()

def scan_and_alert_expiring_items():
    today = timezone.now().date()
    warning_limit = today + timedelta(days=30)
    expiring_tags = MaterialTag.objects.filter(total_pcs__gt=0, expiration_date__lte=warning_limit, expiration_date__gte=today).order_by('expiration_date')
    if not expiring_tags.exists(): return 0 
    
    action_link = reverse('analytics_board')
    notify_web_users_for_event(
        event_name='EXPIRING_STOCKS',
        title="Expiring Materials",
        message=f"{expiring_tags.count()} items are expiring in 30 days.",
        level='WARNING',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='EXPIRING_STOCKS', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            items_data = []
            for tag in expiring_tags:
                items_data.append({'lot_no': tag.lot_no, 'item_code': tag.item_code, 'qty': tag.total_pcs, 'days_left': (tag.expiration_date - today).days})
            subject = f"URGENT: {expiring_tags.count()} Materials Expiring Soon"
            context = {'items': items_data, 'total_count': expiring_tags.count()}
            html_message = render_to_string('Inventory/emails/expiring_stocks_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
            return expiring_tags.count()
    except Exception:
        pass
    return 0

def check_and_alert_low_stock(tag):
    try:
        system_settings = SystemSetting.objects.first()
        threshold = system_settings.low_stock_threshold if system_settings else 50
        
        if tag.total_pcs <= threshold:
            action_link = reverse('stock_inquiry')
            notify_web_users_for_event(
                event_name='LOW_STOCK',
                title="⚠️ Low Stock Warning",
                message=f"Critical! Lot {tag.lot_no} ({tag.item_code}) is down to {tag.total_pcs} pcs.",
                level='WARNING',
                link=action_link
            )
            route = EmailRoute.objects.filter(event_name='LOW_STOCK', is_active=True).first()
            if route:
                target_emails = route.get_email_list()
                if target_emails:
                    subject = f"URGENT: Low Stock Alert - Lot No: {tag.lot_no}"
                    context = {'item_code': tag.item_code, 'description': tag.description, 'lot_no': tag.lot_no, 'current_stock': tag.total_pcs, 'threshold': threshold}
                    html_message = render_to_string('Inventory/emails/low_stock_email.html', context)
                    send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass

def alert_new_po_created(po):
    action_link = reverse('approve_po')
    notify_web_users_for_event(
        event_name='PO_APPROVAL',
        title="NEW P.O. GENERATED",
        message=f"Purchase Order {po.po_no} awaits approval.",
        level='INFO',
        link=action_link
    )
    try:
        route = EmailRoute.objects.get(event_name='PO_APPROVAL', is_active=True)
        target_emails = route.get_email_list()
        if target_emails:
            supplier_name = po.supplier.name if hasattr(po, 'supplier') and po.supplier else "N/A"
            subject = f"NEW P.O. GENERATED: {po.po_no}"
            context = {'po_no': po.po_no, 'supplier_name': supplier_name, 'order_date': po.order_date}
            html_message = render_to_string('Inventory/emails/po_alert_email.html', context)
            send_mail(subject, strip_tags(html_message), settings.DEFAULT_FROM_EMAIL, target_emails, html_message=html_message, fail_silently=False)
    except Exception:
        pass

def scan_and_alert_late_deliveries():
    today = timezone.now().date()
    overdue_pos = PurchaseOrder.objects.filter(
        ordering_status__in=['Approved', 'Pending Approval'], 
        delivery_date__lt=today
    ).order_by('delivery_date')

    if not overdue_pos.exists():
        return 0

    po_data = []
    for po in overdue_pos:
        days_overdue = (today - po.delivery_date).days
        supplier = po.supplier.name if hasattr(po, 'supplier') and po.supplier else "N/A"
        po_data.append({
            'po_no': po.po_no,
            'supplier': supplier,
            'days_late': days_overdue
        })

    # Tatawagin na nito yung notification function natin!
    send_late_delivery_alert(po_data, overdue_pos.count())
    return overdue_pos.count()


def scan_and_alert_low_stock():
    print("\n--- 🚀 RUNNING SMART PREDICTIVE LOW STOCK SCAN ---") 
    sys_settings = SystemSetting.objects.first()
    default_threshold = sys_settings.low_stock_threshold if sys_settings else 50
    
    today = timezone.now().date()
    thirty_days_ago = today - timedelta(days=30)
    OUT_ACTIONS = ['OUT', 'DISPATCH', 'DEDUCT', 'SALE', 'FIFO', 'MINUS', 'SHIPPED', 'CONSUME']

    # 1. Kunin ang Current Stocks
    tag_stocks = MaterialTag.objects.values('item_code').annotate(total_stock=Sum('total_pcs'))
    stock_dict = {str(tag['item_code']).strip().upper(): (tag['total_stock'] or 0) for tag in tag_stocks}

    # 2. Kunin ang Consumption Data (Usage for last 30 days)
    consumption_map = StockLog.objects.filter(
        timestamp__gte=thirty_days_ago,
        action_type__in=OUT_ACTIONS
    ).values('material_tag__item_code').annotate(total_out=Sum('change_qty'))
    
    usage_dict = {c['material_tag__item_code']: abs(float(c['total_out'] or 0)) for c in consumption_map}

    all_items = Item.objects.all()
    low_stock_items = []
    
    for item in all_items:
        code = str(item.item_code).strip().upper()
        current_qty = stock_dict.get(code, 0)
        total_used = usage_dict.get(code, 0)
        
        # Predictive Logic
        adc = total_used / 30.0 # Average Daily Consumption
        dos = (current_qty / adc) if adc > 0 else 999 # Days of Supply

        item_min_stock = getattr(item, 'min_stock', 0)
        threshold_to_use = item_min_stock if item_min_stock > 0 else default_threshold
        
        # 🚩 SMART TRIGGER CONDITION:
        # Mag-a-alert kung: Mababa sa static threshold OR mauubos na sa loob ng 7 araw
        if current_qty <= threshold_to_use or dos <= 7:
            
            # Gagawa tayo ng custom message depende sa urgency
            if dos <= 3:
                urgency = "CRITICAL"
                msg_suffix = f"will run out in {int(dos)} days based on current usage! Reorder IMMEDIATELY."
            elif dos <= 7:
                urgency = "URGENT"
                msg_suffix = f"will run out in {int(dos)} days. Prepare Purchase Order."
            else:
                urgency = "WARNING"
                msg_suffix = f"has reached the minimum threshold ({current_qty} left)."

            full_msg = f"{urgency}: Item {code} {msg_suffix}"

            low_stock_items.append({
                'item_code': code,
                'description': item.description,
                'current_stock': current_qty,
                'threshold': threshold_to_use,
                'dos': int(dos) if dos < 999 else "N/A",
                'adc': round(adc, 1),
                'message': full_msg
            })

            # 🚀 WEB NOTIFICATION TRIGGER (Actionable link papuntang PO)
            notify_web_users_for_event(
                event_name='LOW_STOCK',
                title=f"⚠️ {urgency} Stock Alert",
                message=full_msg,
                level='ERROR' if dos <= 3 else 'WARNING',
                link=reverse('make_po') # Rekta sa P.O. para makabili agad!
            )
            
    if low_stock_items:
        # Ipadala ang listahan sa Email function
        send_low_stock_email_alert(low_stock_items)
            
    print(f"--- SCAN COMPLETED: {len(low_stock_items)} Alerts Triggered ---\n")
    return len(low_stock_items)