from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from Inventory.models import EmailRoute
from Inventory.views import scan_and_alert_expiring_items, scan_and_alert_late_deliveries, scan_and_alert_low_stock

class Command(BaseCommand):
    help = 'Runs all system diagnostic scans (Expiry, Overdue Deliveries, Low Stock).'

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.WARNING('\n=== STARTING DAILY SYSTEM SCAN ==='))

        # 1. Scan for Expiry
        self.stdout.write('Scanning for expiring materials...')
        expiry_count = scan_and_alert_expiring_items() or 0

        # 2. Scan for Late Deliveries
        self.stdout.write('Scanning for overdue deliveries...')
        late_count = scan_and_alert_late_deliveries() or 0

        # 3. Scan for Low Stock
        self.stdout.write('Scanning for low stocks (< 50 pcs)...')
        low_count = scan_and_alert_low_stock() or 0

        # Pagsamahin lahat ng nahanap na issues
        total_issues = expiry_count + late_count + low_count

        # 4. "ALL GOODS" EMAIL LOGIC
        if total_issues == 0:
            self.stdout.write(self.style.SUCCESS("No issues found! Sending 'All Goods' email..."))
            self.send_all_clear_email()
        else:
            self.stdout.write(self.style.ERROR(
                f"\nIssues Found! \n- Expiry Alerts: {expiry_count}\n- Late Deliveries: {late_count}\n- Low Stock: {low_count}"
            ))

        self.stdout.write(self.style.SUCCESS('=== SYSTEM CHECK DONE ===\n'))

    def send_all_clear_email(self):
        """Ito ang magse-send ng email kung walang problema ang system."""
        try:
            route = EmailRoute.objects.get(event_name='TEST_ALERT', is_active=True)
            target_emails = route.get_email_list()

            if target_emails:
                subject = "✅ WMS STATUS: System Scan Complete"
                message = "System Scan Complete. All goods! No expiring items, late deliveries, or low stock materials (< 50 pcs) detected today."
                
                # HTML version
                html_msg = f"""
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 2px solid #10b981; border-radius: 8px; max-width: 500px; background-color: #f0fdfa;">
                    <h2 style="color: #047857; margin-top: 0;">✅ All Systems Go!</h2>
                    <p style="color: #334155; line-height: 1.6;"><strong>System Scan Complete. All goods!</strong></p>
                    <p style="color: #475569; font-size: 14px;">No expiring items, late deliveries, or low stock materials detected today.</p>
                </div>
                """

                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    target_emails,
                    html_message=html_msg,
                    fail_silently=False
                )
                self.stdout.write(self.style.SUCCESS('Email sent successfully!'))
            else:
                self.stdout.write(self.style.ERROR('TEST_ALERT route has no email addresses!'))
        except EmailRoute.DoesNotExist:
            self.stdout.write(self.style.ERROR('TEST_ALERT route is not set up in Django Admin!'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to send all clear email: {e}"))