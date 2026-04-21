from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from .models import SystemAuditLog, SystemNotification, EmailRoute

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
    Saves an Audit Log with IP tracking.
    """
    ip = None
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

    # Siguraduhin na ang 'action' ay naka-UPPERCASE para tumugma sa HTML logic natin
    SystemAuditLog.objects.create(
        user=user if user and user.is_authenticated else None,
        action=action.upper(), 
        module=module.upper(),
        description=description,
        ip_address=ip
    )

def send_in_app_notification(user, title, message, level='INFO', link=None):
    """ 
    Sends notification with level support (INFO, SUCCESS, WARNING, ERROR)
    """
    if user and user.is_active:
        SystemNotification.objects.create(
            user=user,
            title=title,
            message=message,
            level=level.upper(), # 'level' ang mag-trigger ng kulay sa UI natin
            link=link
        )

def notify_admins(title, message, link=None):
    """ Broadcast: Nagpapadala ng alert sa LAHAT ng Admins/Superusers """
    admins = User.objects.filter(is_superuser=True)
    for admin in admins:
        send_in_app_notification(admin, title, message, link)

def send_new_material_request_alert(request_obj):
    """ HTML Email trigger kapag may bagong Material Request """
    print(f"--- EMAIL TRIGGERED FOR REQ: {request_obj.request_no} ---") # 🚀 TERMINAL TRACKER
    
    try:
        route = EmailRoute.objects.get(event_name='NEW_MATERIAL_REQ', is_active=True)
        target_emails = route.get_email_list()
        
        print(f"TARGET EMAILS: {target_emails}") # 🚀 TERMINAL TRACKER
        
        if target_emails:
            subject = f"WMS Alert: New Material Request ({request_obj.request_no})"
            
            # I-RENDER ANG HTML TEMPLATE
            html_content = render_to_string('Inventory/emails/new_material_request.html', {
                'req': request_obj
            })
            text_content = strip_tags(html_content)
            
            # I-SEND GAMIT ANG EMAIL MULTI ALTERNATIVES
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=target_emails
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> EMAIL SUCCESSFULLY SENT TO SMTP! <<<") # 🚀 TERMINAL TRACKER
        else:
            print(">>> FAILED: Walang laman na email addresses sa Admin! <<<") # 🚀 TERMINAL TRACKER
            
    except EmailRoute.DoesNotExist:
        print(">>> FAILED: Walang EmailRoute na 'NEW_MATERIAL_REQ' sa Django Admin! <<<") # 🚀 TERMINAL TRACKER
    except Exception as e:
        print(f">>> CRITICAL EMAIL ERROR: {str(e)} <<<") # 🚀 TERMINAL TRACKER

def send_assembly_completed_alert(machine_obj):
    """ HTML Email trigger kapag natapos buuin ang isang makina (WIP Management) """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR ASSEMBLY: {machine_obj.machine_code} ---")
    
    try:
        route = EmailRoute.objects.get(event_name='ASSEMBLY_COMPLETED', is_active=True)
        target_emails = route.get_email_list()
        
        print(f"TARGET EMAILS: {target_emails}")
        
        if target_emails:
            subject = f"Production Alert: Machine Ready ({machine_obj.machine_code})"
            
            # 🚀 I-RENDER ANG HTML TEMPLATE
            html_content = render_to_string('Inventory/emails/assembly_completed.html', {
                'machine': machine_obj
            })
            text_content = strip_tags(html_content)
            
            # 🚀 I-SEND GAMIT ANG EMAIL MULTI ALTERNATIVES
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=target_emails
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ ASSEMBLY EMAIL SUCCESSFULLY SENT TO SMTP! <<<")
        else:
            print(">>> ❌ FAILED: Walang laman na email addresses sa Admin! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'ASSEMBLY_COMPLETED' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def send_stock_move_alert(tag, old_loc, new_loc, user):
    """ Email trigger kapag may nilipat na stock sa warehouse """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR STOCK MOVE: {tag.lot_no} ---")
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_MOVE', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"Inventory Alert: Stock Moved ({tag.lot_no})"
            
            # I-render ang HTML
            html_content = render_to_string('Inventory/emails/stock_move_email.html', {
                'tag': tag,
                'old_loc': old_loc,
                'new_loc': new_loc,
                'user': user
            })
            text_content = strip_tags(html_content)
            
            msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ STOCK MOVE EMAIL SUCCESSFULLY SENT! <<<")
        else:
            print(">>> ❌ FAILED: Walang nakarehistrong emails sa admin! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'STOCK_MOVE' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def send_stock_correction_alert(tag, old_qty, new_qty, reason, user):
    """ Email trigger kapag may nag-override/nag-correct ng stock sa masterlist """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR STOCK CORRECTION: {tag.lot_no} ---")
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_CORRECTION', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"CRITICAL: Stock Override Alert ({tag.lot_no})"
            
            # Context na tugma din sa ginamit mo sa Test System!
            context = {
                'lot_no': tag.lot_no,
                'item_code': tag.item_code,
                'old_qty': old_qty,
                'new_qty': new_qty,
                'reason': reason,
                'user': user.username if user else "System"
            }
            
            # I-render ang HTML
            html_content = render_to_string('Inventory/emails/stock_correction_email.html', context)
            text_content = strip_tags(html_content)
            
            msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ STOCK CORRECTION EMAIL SUCCESSFULLY SENT! <<<")
        else:
            print(">>> ❌ FAILED: Walang nakarehistrong emails sa admin! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'STOCK_CORRECTION' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def send_stock_out_alert(tag, deduct_qty, remaining_qty, remarks, user):
    """ Email trigger kapag nag-deduct ng item (Stock Out) sa system """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR STOCK OUT: {tag.lot_no} ---")
    
    try:
        route = EmailRoute.objects.get(event_name='STOCK_OUT', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"Inventory Alert: Stock Out ({tag.lot_no})"
            
            context = {
                'lot_no': tag.lot_no,
                'item_code': tag.item_code,
                'deduct_qty': deduct_qty,
                'remaining_qty': remaining_qty,
                'remarks': remarks,
                'user': user.username if user else "System"
            }
            
            html_content = render_to_string('Inventory/emails/stock_out_email.html', context)
            text_content = strip_tags(html_content)
            
            msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ STOCK OUT EMAIL SUCCESSFULLY SENT! <<<")
        else:
            print(">>> ❌ FAILED: Walang nakarehistrong emails sa admin! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'STOCK_OUT' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def send_po_approval_alert(main_po_no, batch_id, po_count, user):
    """ Email trigger kapag may bagong Batch PO na kailangan i-approve """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR PO APPROVAL: {main_po_no} ---")
    
    try:
        # Hahanapin nito yung "Purchase Order Approval Request" sa Admin
        route = EmailRoute.objects.get(event_name='PO_APPROVAL', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"Action Required: PO Approval for {main_po_no}"
            
            context = {
                'main_po_no': main_po_no,
                'batch_id': batch_id,
                'po_count': po_count,
                'user': user.username if user else "System"
            }
            
            html_content = render_to_string('Inventory/emails/po_alert_email.html', context)
            text_content = strip_tags(html_content)
            
            msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ PO APPROVAL EMAIL SUCCESSFULLY SENT! <<<")
        else:
            print(">>> ❌ FAILED: Walang nakarehistrong emails sa admin para sa PO_APPROVAL! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'PO_APPROVAL' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def send_po_approved_notification(batch_id, po_count, creator_email, creator_name, approver_name):
    """ Ipadala ang alert sa nag-draft ng PO kapag na-approve na ito """
    print(f"\n--- 🚀 EMAIL TRIGGERED: PO APPROVED FOR BATCH {batch_id} ---")
    
    if not creator_email:
        print(">>> ❌ FAILED: User who created the PO has no email address. <<<")
        return

    try:
        subject = f"WMS Alert: Your PO Batch {batch_id} is Approved!"
        
        context = {
            'batch_id': batch_id,
            'po_count': po_count,
            'creator_name': creator_name,
            'approver_name': approver_name
        }
        
        html_content = render_to_string('Inventory/emails/po_approved_email.html', context)
        text_content = strip_tags(html_content)
        
        msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [creator_email])
        msg.attach_alternative(html_content, "text/html")
        msg.send(fail_silently=False) 
        
        print(">>> ✅ PO APPROVED EMAIL SUCCESSFULLY SENT TO CREATOR! <<<")
        
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

def alert_new_delivery_request(request_obj):
    """ Email trigger kapag may bagong Delivery Request """
    print(f"\n--- 🚀 EMAIL TRIGGERED FOR NEW DELIVERY REQ: {request_obj.request_no} ---")
    
    try:
        route = EmailRoute.objects.get(event_name='NEW_DELIVERY_REQ', is_active=True)
        target_emails = route.get_email_list()
        
        if target_emails:
            subject = f"Logistics Alert: New Movement Slip ({request_obj.request_no})"
            
            # 👇 DITO NAGKAKAMALI KANINA. TINGNAN MO YUNG 'user', WALA NANG 'requestor'!
            context = {
                'request_no': request_obj.request_no,
                'client_name': request_obj.receiving_place, 
                'delivery_date': request_obj.delivery_date,
                'item_count': request_obj.items.count() if hasattr(request_obj, 'items') else 0,
                'reason': request_obj.reason,
                'user': "System User" # 🚀 FIX: Hardcoded text na para iwas database error
            }
            
            html_content = render_to_string('Inventory/emails/delivery_request_email.html', context)
            text_content = strip_tags(html_content)
            
            msg = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, target_emails)
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False) 
            
            print(">>> ✅ NEW DELIVERY REQ EMAIL SUCCESSFULLY SENT! <<<")
        else:
            print(">>> ❌ FAILED: Walang nakarehistrong emails sa admin! <<<")
            
    except EmailRoute.DoesNotExist:
        print(">>> ❌ FAILED: Walang EmailRoute na 'NEW_DELIVERY_REQ' sa Django Admin! <<<")
    except Exception as e:
        print(f">>> 🔥 CRITICAL EMAIL ERROR: {str(e)} <<<")

        