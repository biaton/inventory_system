from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import random

class PasswordResetOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=5)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        # 10 minutes validity
        return self.created_at >= timezone.now() - timedelta(minutes=10)

    def generate_otp(self):
        # Gagawa ng random 5-digit number (e.g., 49201)
        self.otp = str(random.randint(10000, 99999))
        self.created_at = timezone.now()
        self.save()
        
class Item(models.Model):
    UOM_CHOICES = [
        ('PCS', 'Pieces'),
        ('KGS', 'Kilograms'),
        ('MTR', 'Meters'),
        ('SET', 'Full Set'),
        ('BOX', 'Boxes'),
        ('ROLL', 'Rolls'),
    ]
    CATEGORY_CHOICES = [
        ('RAW', 'Raw Materials'),
        ('CON', 'Consumables'),
        ('FG', 'Finished Goods'),
        ('PK', 'Packaging Materials'),
        ('SCRAP', 'Scrap/Waste'),
    ]

    item_code = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    uom = models.CharField(max_length=10, choices=UOM_CHOICES, default='PCS')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='RAW')
    min_stock = models.IntegerField(default=0, help_text="Minimum level for low stock alerts")
    unit_price = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)

    brand = models.CharField(max_length=100, blank=True, null=True)
    category = models.CharField(max_length=100, blank=True, null=True)
    
    # 🚀 BAGO PARA SA WMS:
    default_zone = models.CharField(max_length=100, blank=True, null=True, help_text="Primary storage location")
    updated_at = models.DateTimeField(auto_now=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.item_code

class Contact(models.Model):
    TYPES = (('Customer', 'Customer'), ('Supplier', 'Supplier'))
    name = models.CharField(max_length=200, unique=True)
    contact_type = models.CharField(max_length=20, choices=TYPES) 
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    contact_person = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # 🚀 BAGO PARA SA WMS LOGISTICS:
    contact_code = models.CharField(max_length=50, blank=True, null=True, help_text="Client ID / Barcode")
    route_code = models.CharField(max_length=100, blank=True, null=True, help_text="Logistics Routing Zone (e.g. METRO MANILA, NORTH)")
    preferred_transport = models.CharField(max_length=50, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.contact_type})"

class CustomerOrder(models.Model):
    # Options base sa instruction mo
    ORDER_TYPES = [('Standard', 'Standard'), ('Express', 'Express'), ('Schedule', 'Schedule'), ('Pick up', 'Pick up')]
    ORDER_STATUS = [
        ('Valid', 'Valid'), ('Pending', 'Pending'), ('Processing', 'Processing'),
        ('Shipped', 'Shipped'), ('Delivered', 'Delivered'), ('In Transit', 'In Transit'),
        ('Out for delivery', 'Out for delivery'), ('Cancelled', 'Cancelled'), ('Failed delivery', 'Failed delivery')
    ]
    TRANSPORT_MODES = [
        ('Motorcycle', 'Motorcycle'), ('Van', 'Van'), ('Truck', 'Truck'),
        ('Cargo Ship', 'Cargo Ship'), ('Cargo plane', 'Cargo plane'), ('Train', 'Train')
    ]

    # Header Info
    order_no = models.CharField(max_length=100) 
    cust_po_no = models.CharField(max_length=100, blank=True, null=True)
    delivery_date = models.DateField(blank=True, null=True)
    customer = models.ForeignKey('Contact', on_delete=models.CASCADE) # Siguraduhing may Contact model ka
    order_date = models.DateField() 
    order_type = models.CharField(max_length=20, choices=ORDER_TYPES, default='Standard')
    order_status = models.CharField(max_length=50, choices=ORDER_STATUS, default='Pending')
    description = models.CharField(max_length=255, blank=True, null=True)
    contact_person = models.CharField(max_length=150, blank=True, null=True)
    delivery_address = models.TextField(blank=True, null=True)
    
    # Line Item Info (Flat table setup for Customer Orders)
    item_code = models.CharField(max_length=100)
    cust_item_code = models.CharField(max_length=100, blank=True, null=True)
    quantity = models.IntegerField(default=0)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    transport = models.CharField(max_length=50, choices=TRANSPORT_MODES, default='Motorcycle')
    remarks = models.TextField(blank=True, null=True)
    
    batch_id = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return f"{self.order_no} - {self.item_code}"


# ==========================================
# MALINIS NA PURCHASE ORDER (HEADER ONLY)
# ==========================================
class PurchaseOrder(models.Model):
    TAX_TERMS = [
        ('VAT Inclusive', 'VAT Inclusive'), 
        ('Taxable', 'Taxable'), 
        ('Non-taxable', 'Non-taxable'),
        ('Tax Exempt', 'Tax Exempt'),
        ('VAT Exclusive', 'VAT Exclusive'),
        ('Zero-Rated', 'Zero-Rated')
    ]
    CURRENCIES = [('PHP', 'PHP'), ('USD', 'USD'), ('JPY', 'JPY')]
    
    batch_id = models.CharField(max_length=50, null=True, blank=True)
    po_no = models.CharField(max_length=100)
    supplier = models.ForeignKey('Supplier', on_delete=models.CASCADE, related_name='purchase_orders')
    
    # Dates & Logistics
    order_date = models.DateField()
    delivery_date = models.DateField(null=True, blank=True)
    transport = models.CharField(max_length=50, default='Truck')
    
    # Finance
    tax_term = models.CharField(max_length=50, choices=TAX_TERMS, default='VAT Inclusive')
    currency = models.CharField(max_length=10, choices=CURRENCIES, default='PHP')
    discount_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Summary Totals
    po_amount_total = models.DecimalField(max_digits=20, decimal_places=2, default=0.00)
    tax_amount_total = models.DecimalField(max_digits=20, decimal_places=2, default=0.00)
    grand_total = models.DecimalField(max_digits=20, decimal_places=2, default=0.00)
    
    # Status & Others
    ordering_status = models.CharField(max_length=50, default='Draft')
    remarks = models.TextField(blank=True, null=True)
    version = models.CharField(max_length=10, default='1.0')
    
    # Supplier Confirmations
    supplier_so_no = models.CharField(max_length=100, null=True, blank=True)
    confirmed_date = models.DateField(null=True, blank=True)
    est_delivery_date = models.DateField(null=True, blank=True)
    confirmation_remarks = models.TextField(null=True, blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_pos')

    def __str__(self):
        return f"{self.po_no} - {self.supplier.name}"


# ==========================================
# PURCHASE ORDER ITEMS (LINES ONLY)
# ==========================================
class PurchaseOrderItem(models.Model):
    purchase_order = models.ForeignKey(PurchaseOrder, on_delete=models.CASCADE, related_name='items')
    
    item_code = models.CharField(max_length=100)
    description = models.CharField(max_length=255, null=True, blank=True)
    packing = models.CharField(max_length=50, null=True, blank=True)
    moq = models.IntegerField(default=0)
    n_qty = models.IntegerField(default=1)
    container_unit = models.IntegerField(default=1)
    
    qty = models.IntegerField(default=0)
    qty_received = models.IntegerField(default=0)
    unit_price = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    
    status = models.CharField(max_length=50, default='Pending')
    is_amortized = models.BooleanField(default=False)

    confirmed_qty = models.IntegerField(null=True, blank=True)
    confirmed_unit_price = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    confirmed_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return f"{self.item_code} ({self.qty} pcs) for PO: {self.purchase_order.po_no}"

# ==========================================
# 1. WAREHOUSE LOCATIONS (Storage)
# ==========================================
class Location(models.Model):
    place_name = models.CharField(max_length=100) # Hal: Main Warehouse, Sub-Depot
    rack_bin = models.CharField(max_length=50, unique=True) # Hal: RACK-A12
    description = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.place_name} - {self.rack_bin}"

# 2. MATERIAL TAG / INVENTORY STOCK
class MaterialTag(models.Model):
    # Naka-link sa PO para madaling hugutin ang data sa "Output" button
    po_reference = models.ForeignKey('PurchaseOrder', on_delete=models.SET_NULL, null=True, blank=True)
    item_code = models.CharField(max_length=50)
    description = models.CharField(max_length=255)
    remarks = models.TextField(blank=True, null=True)
    
    # Identification
    invoice_no = models.CharField(max_length=100, blank=True, null=True)
    lot_no = models.CharField(max_length=100) # Ang ita-type/scan ng user
    revision = models.CharField(max_length=50, blank=True, null=True)
    
    # Status & Dates
    inspection_status = models.CharField(max_length=50, default="Pending") # Passed, Failed
    arrival_date = models.DateField(default=timezone.now)
    expiration_date = models.DateField(null=True, blank=True)
    
    # Quantities & Packing
    packing_type = models.CharField(max_length=20, default="PCS") # PCS, BOX, PALLET
    container_count = models.IntegerField(default=1)
    total_pcs = models.IntegerField(default=0) # DITO TAYO MAGBABAWAS KAPAG NAG-PICKING!
    
    # Storage Location (Maa-update ito sa "Storage" tab)
    #location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True)
    location = models.ForeignKey('LocationMaster', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.item_code} | LOT: {self.lot_no} | QTY: {self.total_pcs}"

# 3. DELIVERY REQUEST HEADER
class DeliveryRequest(models.Model):
    request_no = models.CharField(max_length=50, unique=True) # Hal: REQ-2026-001
    request_date = models.DateField(default=timezone.now)
    delivery_date = models.DateField()
    delivery_place = models.CharField(max_length=100) # Saan galing? (Origin)
    receiving_place = models.CharField(max_length=100) # Saan dadalhin? (Destination)
    reason = models.CharField(max_length=100)
    
    model_name = models.CharField(max_length=100, blank=True, null=True)
    production_no = models.CharField(max_length=100, blank=True, null=True)
    maker = models.CharField(max_length=100, blank=True, null=True)
    part_name = models.CharField(max_length=150, blank=True, null=True)
    po_no = models.CharField(max_length=100, blank=True, null=True)

    remarks = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default="Pending") 

    def __str__(self):
        return f"{self.request_no} - {self.status}"

# 4. DELIVERY REQUEST ITEMS
class DeliveryRequestItem(models.Model):
    # FIX: Isang ForeignKey na lang dito papunta sa DeliveryRequest
    request_header = models.ForeignKey(DeliveryRequest, related_name='items', on_delete=models.CASCADE)
    item_code = models.CharField(max_length=50)
    description = models.TextField(null=True, blank=True) 
    revision = models.CharField(max_length=50, blank=True, null=True)
    request_qty = models.IntegerField(default=0)
    delivered_qty = models.IntegerField(default=0) 
    remarks = models.TextField(blank=True, null=True) # Added from your previous code

    def __str__(self):
        return f"{self.item_code} for {self.request_header.request_no}"

class StockLog(models.Model):
    ACTION_CHOICES = [
        ('REG', 'Registration'),
        ('MOVE', 'Stock Move'),
        ('CORR', 'Correction'),
        ('OUT', 'Stock Out'),
    ]

    material_tag = models.ForeignKey(MaterialTag, on_delete=models.CASCADE, related_name='logs')
    action_type = models.CharField(max_length=10, choices=ACTION_CHOICES)
    old_qty = models.IntegerField()
    new_qty = models.IntegerField()
    change_qty = models.IntegerField() # Ilan ang nadagdag/nabawas
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

class SystemSetting(models.Model):
    low_stock_threshold = models.IntegerField(default=50)
    enable_email_alerts = models.BooleanField(default=False)
    warehouse_name = models.CharField(max_length=100, default="Main Warehouse")
    
    def __str__(self):
        return "System Configuration"

class ShipmentSchedule(models.Model):
    shipment_no = models.CharField(max_length=50, unique=True)
    
    # MGA BAGONG DAGDAG PARA SA UI MO:
    customer = models.ForeignKey(Contact, on_delete=models.SET_NULL, null=True, blank=True, limit_choices_to={'contact_type': 'Customer'})
    invoice_no = models.CharField(max_length=100, blank=True, null=True)
    transport = models.CharField(max_length=50, blank=True, null=True)
    
    # YUNG MGA DATI MONG FIELDS:
    item_code = models.CharField(max_length=100)
    destination = models.CharField(max_length=255)
    quantity = models.IntegerField()
    schedule_date = models.DateField()
    status = models.CharField(max_length=20, default='Pending') # Pending, Confirmed, Shipped
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.shipment_no} - {self.item_code}"

class ItemMaster(models.Model):
    item_code = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255)
    category = models.CharField(max_length=100, default='Raw Material') # Hal. Packaging, Finished Goods
    uom = models.CharField(max_length=20, default='PCS') # Unit of Measure (PCS, KGS, BOX)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.item_code} - {self.description}"

class LocationMaster(models.Model):
    location_code = models.CharField(max_length=50, unique=True) # Hal. RACK-A1
    warehouse = models.CharField(max_length=100, blank=True, null=True) # NEW: Hal. MAIN WHSE
    zone = models.CharField(max_length=100, blank=True)
    zone_type = models.CharField(max_length=100, blank=True, null=True) # NEW: Hal. COLD STORAGE, DRY
    capacity = models.IntegerField(default=0) # NEW: Max items na kasya
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.location_code

# ==========================================
# 3. SUPPLIER MASTER MODEL
# ==========================================
class Supplier(models.Model):
    name = models.CharField(max_length=255)
    vendor_code = models.CharField(max_length=50, unique=True)
    contact_name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    
    # 🚀 BAGO PARA SA WMS LOGISTICS:
    address = models.TextField(blank=True, null=True, help_text="Supplier's physical address for routing")
    avg_lead_time = models.IntegerField(default=7, help_text="Average delivery days")
    is_active = models.BooleanField(default=True, help_text="Uncheck to deactivate vendor")

    def __str__(self):
        return f"{self.vendor_code} | {self.name}"

class Profile(models.Model):
    # ETO NA YUNG BAGONG RBAC ROLES MO:
    ROLE_CHOICES = [
        ('SYSTEM_ADMIN', 'System Administrator'),
        ('OWNER', 'Management / Owner'),
        ('INV_MANAGER', 'Inventory Manager'),
        ('WH_STAFF', 'Warehouse Staff'),
        ('PURCHASING', 'Purchasing Officer'),
        ('SUPPLY_CHAIN', 'Supply Chain'),
        ('SALES', 'Sales Staff'),
        ('ACCOUNTING', 'Accounting'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='WH_STAFF')
    company_name = models.CharField(max_length=255, blank=True, null=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"

class EmailRoute(models.Model):
    # (Yung EVENT_CHOICES mo, same lang, walang babaguhin dito)
    EVENT_CHOICES = [
        ('TEST_ALERT', 'System Test & Diagnostics'),
        ('LOW_STOCK', 'Low Stock / Critical Level Alert'),
        ('PO_APPROVAL', 'Purchase Order Approval Request'),
        ('NEW_USER', 'New User Registration Alert'),
        ('EXPIRING_STOCKS', 'Expiring Materials Warning (30 Days)'),
        ('SECURITY_ALERT', 'Security: Multiple Failed Login Attempts'),
        ('QC_FAILED', 'Quality Control: Material Rejected/Failed Alert'),
        ('LATE_DELIVERY', 'Logistics: Overdue / Late Delivery Alert'),
        ('STOCK_CORRECTION', 'Inventory: Manual Stock Override/Correction Alert'),
        ('NEW_DELIVERY_REQ', 'Logistics: New Movement Slip / Transfer Request'),
        ('NEW_MATERIAL_REQ', 'Warehouse: New Material Request Submitted'),
        ('ASSEMBLY_COMPLETED', 'Production: Machine Assembly Completed'),
        ('STOCK_MOVE', 'Inventory: Item Location Transfer Alert'),
        ('STOCK_OUT', 'Inventory: Stock Issuance / Deduction Alert'),
        ('QC_PENDING', 'Quality Control: Pending Inspections Reminder'),
        ('AGING_REQUESTS', 'Warehouse: Unfulfilled/Aging Requests Alert'),
        ('DEAD_STOCK', 'Finance: Dead / Slow-Moving Stock Alert'),
    ]
    
    event_name = models.CharField(max_length=50, choices=EVENT_CHOICES, unique=True, verbose_name="Notification Event")
    
    # 🚀 BAGO: Ito na yung papalit sa target_emails
    target_users = models.ManyToManyField(
        User, 
        blank=True, 
        related_name='email_subscriptions',
        help_text="Select users who should receive this notification."
    )
    
    is_active = models.BooleanField(default=True, help_text="Uncheck this to temporarily disable sending emails for this event.")

    def __str__(self):
        return f"{self.get_event_name_display()} Routing"

    # 🚀 BAGO: Kukunin niya yung email ng bawat user na naka-check sa system natin
    def get_email_list(self):
        # I-exclude natin yung mga users na walang naka-set na email para iwas error sa sending
        return list(self.target_users.exclude(email__exact='').values_list('email', flat=True))

def send_shipping_notification(order_no, customer_email, courier_name, tracking_number):
    if not customer_email:
        return False # Wag mag-send kung walang email ang customer
        
    try:
        subject = f"Your Order {order_no} has been Shipped!"
        message = f"""
        Hello,
        
        Good news! Your order {order_no} has been handed over to our logistics partner.
        
        Shipping Details:
        - Courier: {courier_name}
        - Tracking Number: {tracking_number}
        
        You can use the tracking number to monitor your delivery.
        Thank you for trusting ASIA Integrated Corp.!
        """
        
        send_mail(
            subject, 
            message, 
            django_settings.DEFAULT_FROM_EMAIL, 
            [customer_email], # Direktang ise-send sa email ng customer
            fail_silently=False
        )
        return True
    except Exception as e:
        print(f"Failed to send shipping email to customer: {str(e)}")
        return False

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    # ETO YUNG PINAKA-IMPORTANTE NA TAMA:
    if created:
        Profile.objects.get_or_create(user=instance)
    elif not hasattr(instance, 'profile'):
        Profile.objects.get_or_create(user=instance)

class SystemAuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'User Login'),
        ('CREATE', 'Created Record'),
        ('UPDATE', 'Modified/Edited'),
        ('DELETE', 'Deleted Record'),
        ('SYSTEM', 'System Event'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    module = models.CharField(max_length=100) # Hal: 'Purchase Order', 'Item Master', 'Settings'
    description = models.TextField() # Hal: 'Edited unit price of Item RAW-001 from 50 to 55'
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True) # Dagdag security, saan siya nag-login!

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} - {self.action} - {self.module} at {self.timestamp}"

class SystemNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=100)
    message = models.TextField()
    link = models.CharField(max_length=255, blank=True, null=True) # URL kung saan pupunta kapag kinlick
    is_read = models.BooleanField(default=False)
    level = models.CharField(max_length=20, default='info')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at'] # Laging nasa taas ang pinakabago

    def __str__(self):
        return f"[{self.is_read}] {self.user.username} - {self.title}"

# models.py (Idagdag sa dulo)

class MachineAsset(models.Model):
    STATUS_CHOICES = [
        ('Building', 'Building / Incomplete'),
        ('Available', 'Available / Complete'),
        ('Partial', 'Partial / Missing Parts'),
        ('Dismantled', 'Dismantled / Cannibalized'),
        ('Deployed', 'Deployed to Client')
    ]

    machine_code = models.CharField(max_length=50, unique=True, verbose_name="Machine Serial/Code")
    name = models.CharField(max_length=200, verbose_name="Machine Name/Model")
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Building')
    
    # Sino nagbuo at kailan ginawa
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.machine_code} - {self.name}"

    def update_status(self):
        """
        Dito natin ilalagay yung 'State Engine' mo in the future
        para automatic na magpalit ng status base sa laman niyang parts.
        """
        pass


class MachineComponent(models.Model):
    ACTION_CHOICES = [
        ('Assemble', 'Assemble (Install to Machine)'),
        ('Dismantle', 'Dismantle (Remove from Machine)')
    ]

    machine = models.ForeignKey(MachineAsset, on_delete=models.CASCADE, related_name='components')
    # Iko-konekta natin sa Material Tag kasi yun ang specific physical stock mo!
    material_tag = models.ForeignKey('MaterialTag', on_delete=models.PROTECT, related_name='machine_usages')
    
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    qty = models.DecimalField(max_digits=10, decimal_places=2, default=1)
    
    # Sino nagkabit/nagbaklas at kailan
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    remarks = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.action} {self.qty}x {self.material_tag.item_code} on {self.machine.machine_code}"

class SystemModule(models.Model):
    MODULE_CHOICES = [
        ('CUSTOMER_ORDER', 'Customer Order'),
        ('PURCHASE_ORDER', 'Purchase Order'),
        ('RECEIVING', 'Receiving & Inspection'),
        ('INV_REQUEST', 'Inventory Request'),
        ('INV_PROCESSING', 'Inventory Processing'),
        ('INV_INQUIRY', 'Inventory Inquiry'),
        ('ASSET_WIP', 'Asset & WIP Management'),
        ('USER_MASTER', 'User Master'),
        ('SYSTEM_ANALYTICS', 'System Analytics'),
        ('SYS_CONFIG', 'System Configuration'),
    ]

    code = models.CharField(max_length=50, choices=MODULE_CHOICES, unique=True)
    name = models.CharField(max_length=100) # Hal. "Customer Order"
    description = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class UserAccess(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='access_rights')
    allowed_modules = models.ManyToManyField('SystemModule', blank=True, related_name='authorized_users')
    
    is_super_admin = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='granted_accesses')

    def __str__(self):
        return self.user.username

    @property
    def active_module_codes(self):
        return [m.code for m in self.allowed_modules.all()]

class FleetDriver(models.Model):
    name = models.CharField(max_length=100, unique=True)
    contact_no = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class Vehicle(models.Model):
    VEHICLE_TYPES = [
        ('Truck', 'Truck'),
        ('Van', 'Van'),
        ('Motorcycle', 'Motorcycle'),
    ]
    STATUS_CHOICES = [
        ('Available', 'Available'),
        ('In Transit', 'In Transit'),
        ('Maintenance', 'Maintenance'),
    ]
    CODING_DAYS = [
        ('Monday', 'Monday (1, 2)'),
        ('Tuesday', 'Tuesday (3, 4)'),
        ('Wednesday', 'Wednesday (5, 6)'),
        ('Thursday', 'Thursday (7, 8)'),
        ('Friday', 'Friday (9, 0)'),
        ('None', 'None (Exempted)'),
    ]

    plate_number = models.CharField(max_length=20, unique=True)
    vehicle_type = models.CharField(max_length=50, choices=VEHICLE_TYPES)
    capacity_kg = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    coding_day = models.CharField(max_length=20, choices=CODING_DAYS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Available')
    driver_name = models.CharField(max_length=100, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.plate_number} ({self.vehicle_type})"

class Vehicle(models.Model):
    VEHICLE_TYPES = [
        ('Truck', 'Truck'),
        ('Van', 'Van'),
        ('Motorcycle', 'Motorcycle'),
    ]
    STATUS_CHOICES = [
        ('Available', 'Available'),
        ('In Transit', 'In Transit'),
        ('Maintenance', 'Maintenance'),
    ]
    CODING_DAYS = [
        ('Monday', 'Monday (1, 2)'),
        ('Tuesday', 'Tuesday (3, 4)'),
        ('Wednesday', 'Wednesday (5, 6)'),
        ('Thursday', 'Thursday (7, 8)'),
        ('Friday', 'Friday (9, 0)'),
        ('None', 'None (Exempted)'),
    ]

    plate_number = models.CharField(max_length=20, unique=True)
    vehicle_type = models.CharField(max_length=50, choices=VEHICLE_TYPES)
    capacity_kg = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    coding_day = models.CharField(max_length=20, choices=CODING_DAYS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Available')
    driver_name = models.CharField(max_length=100, blank=True, null=True)
    lto_expiry = models.DateField(null=True, blank=True)
    pms_schedule = models.DateField(null=True, blank=True)
    assigned_driver = models.ForeignKey(FleetDriver, on_delete=models.SET_NULL, null=True, blank=True)
    assistant_name = models.CharField(max_length=100, blank=True, null=True)
    
    
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.plate_number} ({self.vehicle_type})"

# 🚀 BAGO: Tracker para sa Gas at Toll
class TripExpense(models.Model):
    vehicle = models.ForeignKey(Vehicle, on_delete=models.SET_NULL, null=True)
    order_batch_no = models.CharField(max_length=50) # Main PO No.
    fuel_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    toll_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    date_recorded = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Expense for {self.order_batch_no} - {self.vehicle}"