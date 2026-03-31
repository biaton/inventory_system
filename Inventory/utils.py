from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from .models import SystemAuditLog, SystemNotification

def send_shipping_notification(order_no, customer_email, courier_name, tracking_number=""):
    if not customer_email:
        return False

    subject = f"Shipping Update: Order #{order_no} is on its way!"
    tracking_info = f"\nTracking Number: {tracking_number}" if tracking_number else ""
    
    message = f"""
    Hello,

    Good news! Your order #{order_no} has been packed and handed over to our logistics partner.

    Courier: {courier_name} {tracking_info}

    Please expect your delivery soon. Thank you!

    Best regards,
    ASIA Integrated Machine Inc.
    """

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [customer_email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send shipping email: {e}")
        return False

def send_order_acknowledgement(order_no, customer_email, total_amount, item_count):
    if not customer_email:
        return False

    subject = f"Order Confirmation: #{order_no} Received"
    message = f"""
    Hello,

    Thank you for your order! We have received your purchase request.

    Order Summary:
    - Order No: {order_no}
    - Total Items: {item_count}
    - Grand Total: PHP {total_amount:,.2f}

    Our warehouse team will now begin processing your order. You will receive another update once it is ready for shipping.

    Best regards,
    ASIA Integrated Corp.
    """

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [customer_email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send acknowledgment for Order {order_no}: {e}")
        return False

def send_qc_rejection_alert(material_tag):
    try:
        # 1. Kunin ang routing para sa QC_FAILED
        route = EmailRoute.objects.get(event_name='QC_FAILED', is_active=True)
        recipient_list = route.get_email_list()

        if not recipient_list:
            return

        # 2. I-construct ang email
        subject = f"🚨 URGENT QC ALERT: Material Rejected - {material_tag.item_code}"
        
        message = f"""
        ATTENTION: Quality Control Department

        A material has failed inspection and requires immediate attention.

        DETAILS:
        - PO Reference: {material_tag.po_reference.po_no if material_tag.po_reference else 'N/A'}
        - Item Code: {material_tag.item_code}
        - Description: {material_tag.description}
        - Lot Number: {material_tag.lot_no}
        - Quantity: {material_tag.total_pcs}
        - Arrival Date: {material_tag.arrival_date}
        - Storage Location: {material_tag.location.location_code if material_tag.location else 'UNASSIGNED'}

        Please log in to the system to review the rejection remarks and take necessary action.

        System Notification
        ASIA Integrated Machine Inc.
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
            fail_silently=False,
        )
    except EmailRoute.DoesNotExist:
        print("QC_FAILED email route is not configured.")
    except Exception as e:
        print(f"Failed to send QC alert: {e}")

def log_system_action(user, action, module, description, request=None):
    """
    Shortcut para mag-save ng Audit Log.
    """
    ip = None
    if request:
        # Kunin ang IP address ng user para sa security tracking
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

    SystemAuditLog.objects.create(
        user=user if user.is_authenticated else None,
        action=action,
        module=module,
        description=description,
        ip_address=ip
    )

def send_in_app_notification(user, title, message, link=None):
    """ Shortcut para mag-send ng bell notification sa isang specific user """
    if user and user.is_active:
        SystemNotification.objects.create(
            user=user,
            title=title,
            message=message,
            link=link
        )

def notify_admins(title, message, link=None):
    """ Broadcast: Nagpapadala ng alert sa LAHAT ng Admins/Superusers """
    admins = User.objects.filter(is_superuser=True)
    for admin in admins:
        send_in_app_notification(admin, title, message, link)
        