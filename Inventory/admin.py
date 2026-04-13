from django.contrib import admin
from django.contrib.auth.models import User
from .models import (
    Profile, Item, Location, Supplier, Contact, 
    CustomerOrder, PurchaseOrder, PurchaseOrderItem, 
    MaterialTag, DeliveryRequest, DeliveryRequestItem, 
    StockLog, ShipmentSchedule, SystemSetting, EmailRoute, LocationMaster, SystemAuditLog
)

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'company_name', 'contact_number')
    search_fields = ('user__username', 'role', 'company_name')
    list_filter = ('role',)

@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ('item_code', 'description', 'uom', 'category', 'min_stock')
    search_fields = ('item_code', 'description')

# ==========================================
# CLIENTS (Gamit ang Contact model)
# ==========================================
@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'contact_type', 'email', 'phone')
    search_fields = ('name',)
    list_filter = ('contact_type',) # Dito mo pwedeng i-filter kung 'Customer' ba sila

@admin.register(CustomerOrder)
class CustomerOrderAdmin(admin.ModelAdmin):
    list_display = ('order_no', 'customer', 'item_code', 'quantity', 'unit_price', 'amount', 'order_date', 'order_status')
    search_fields = ('order_no', 'item_code', 'customer__name')
    list_filter = ('order_status', 'transport', 'order_date')
    readonly_fields = ('amount',) 

    def save_model(self, request, obj, form, change):
        obj.amount = obj.quantity * obj.unit_price
        super().save_model(request, obj, form, change)

class PurchaseOrderItemInline(admin.TabularInline):
    model = PurchaseOrderItem
    extra = 0
    readonly_fields = ('amount',)

# ==========================================
# SUPPLIERS
# ==========================================
@admin.register(Supplier)
class SupplierAdmin(admin.ModelAdmin):
    list_display = ('vendor_code', 'name', 'contact_name', 'email')
    search_fields = ('vendor_code', 'name', 'contact_name')

@admin.register(PurchaseOrder)
class PurchaseOrderAdmin(admin.ModelAdmin):
    list_display = ('po_no', 'supplier', 'order_date', 'ordering_status', 'currency')
    search_fields = ('po_no', 'supplier__name', 'remarks')
    list_filter = ('ordering_status', 'order_date', 'currency')
    inlines = [PurchaseOrderItemInline]
    fieldsets = (
        ('Header Information', {'fields': ('po_no', 'supplier', 'ordering_status')}),
        ('Dates & Logistics', {'fields': ('order_date', 'delivery_date', 'transport', 'tax_term')}),
        ('Finance & Others', {'fields': ('currency', 'discount_rate', 'remarks')}),
    )

@admin.register(PurchaseOrderItem)
class PurchaseOrderItemAdmin(admin.ModelAdmin):
    list_display = ('purchase_order', 'item_code', 'qty', 'unit_price', 'amount')
    search_fields = ('item_code', 'purchase_order__po_no')

class DeliveryRequestItemInline(admin.TabularInline):
    model = DeliveryRequestItem
    extra = 0

@admin.register(DeliveryRequest)
class DeliveryRequestAdmin(admin.ModelAdmin):
    list_display = ('request_no', 'delivery_place', 'receiving_place', 'delivery_date', 'status')
    search_fields = ('request_no', 'delivery_place', 'receiving_place')
    list_filter = ('status', 'delivery_date')
    inlines = [DeliveryRequestItemInline]

@admin.register(MaterialTag)
class MaterialTagAdmin(admin.ModelAdmin):
    list_display = ('item_code', 'lot_no', 'total_pcs', 'packing_type', 'location', 'inspection_status')
    search_fields = ('item_code', 'lot_no', 'po_reference__po_no')
    list_filter = ('inspection_status', 'packing_type')

@admin.register(LocationMaster)
class LocationMasterAdmin(admin.ModelAdmin):
    list_display = ('location_code', 'zone', 'description')
    search_fields = ('location_code', 'zone', 'description')
    list_filter = ('zone',)
    ordering = ('zone', 'location_code')

@admin.register(StockLog)
class StockLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action_type', 'material_tag', 'change_qty', 'user')
    list_filter = ('action_type', 'timestamp')
    search_fields = ('material_tag__lot_no', 'material_tag__item_code')
    readonly_fields = ('timestamp',)

@admin.register(ShipmentSchedule)
class ShipmentScheduleAdmin(admin.ModelAdmin):
    list_display = ('shipment_no', 'customer', 'invoice_no', 'item_code', 'quantity', 'transport', 'status', 'schedule_date')
    list_filter = ('status', 'transport', 'schedule_date')
    search_fields = ('shipment_no', 'item_code', 'invoice_no', 'destination')
    ordering = ('-schedule_date',)

@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ('warehouse_name', 'low_stock_threshold', 'enable_email_alerts')

@admin.register(EmailRoute)
class EmailRouteAdmin(admin.ModelAdmin):
    # Pinalitan natin yung 'target_emails' ng custom function natin na 'get_target_users'
    list_display = ('event_name', 'get_target_users', 'is_active')
    
    # 🚀 BAGO: Pampaganda ng UI sa Django Admin para madali mag-select ng users
    filter_horizontal = ('target_users',) 

    # Function para pagsama-samahin yung pangalan ng mga naka-assign na users
    def get_target_users(self, obj):
        users = obj.target_users.all()
        if users:
            return ", ".join([user.username for user in users])
        return "No Users Assigned"
    
    get_target_users.short_description = 'Target Users'