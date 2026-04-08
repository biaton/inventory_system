from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Login and Logout
    path('login/', views.custom_login_view, name='login'),
    path('logout/', views.custom_logout_view, name='logout'),

    # dashboard
    path('profile/', views.view_profile, name='view_profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('dashboard/', views.dashboard_view, name='dashboard'), 

    # notifications
    path('notification/read/<int:notif_id>/', views.read_notification_view, name='read_notification'),
    path('notifications/all/', views.all_notifications_view, name='all_notifications'),
    path('notifications/mark-all-read/', views.mark_all_read_view, name='mark_all_read'),

    # analytics
    path('analytics/', views.analytics_view, name='analytics_board'),
    
    # 1. USER & CUSTOMER MASTER
    # Siguraduhin na 'user_master' ang name para tugma sa master_base.html
    path('master/users/', views.user_master_view, name='user_master'), 
    path('master/users/register/', views.register_user_view, name='register_user'),
    path('master/users/edit/<int:user_id>/', views.edit_user, name='edit_user'),
    path('master/users/toggle/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('master/users/export/', views.export_users_csv, name='export_users_csv'),
    path('master/users/change-password/', views.change_password_view, name='change_password'),

    # 2. ITEM MASTER
    # Inisa lang natin ang name para hindi mag-error (item_master)
    path('master/items/', views.item_master_view, name='item_master'),
    path('master/items/register/', views.register_item_view, name='register_item'),
    path('master/items/edit/<int:pk>/', views.edit_item, name='edit_item'),
    path('master/items/delete/<int:pk>/', views.delete_item, name='delete_item'),
    path('master/items/export/', views.export_items_view, name='export_items'),

    # 3. LOCATION MASTER
    path('master/locations/', views.location_master_view, name='location_master'),

    # 4. SUPPLIER MASTER
    path('master/suppliers/', views.supplier_master, name='supplier_master'),
    path('master/suppliers/register/', views.register_supplier, name='register_supplier'),
    # Dagdag natin ito para sa action button ng supplier
    path('master/suppliers/edit/<int:pk>/', views.edit_supplier, name='edit_supplier'),

    # 4. CUSTOMER MASTER
    path('master/customers/register/', views.register_customer_view, name='register_customer'),
    path('master/customers/', views.customer_master_view, name='customer_master'),

    # 5. SYSTEM SETTINGS
    # Siguraduhin na 'settings_master' ang name para sa huling tab
    path('master/settings/', views.settings_master_view, name='settings_master'),

    # change password
    path('settings/change-password/', views.change_password_view, name='change_password'),
    
    # Customer Orders 
    path('order-input-manual/', views.order_input_manual_view, name='order_manual'),
    path('po-confirmation/', views.po_confirmation_view, name='po_confirmation'),
    path('order-excel/', views.order_input_excel_view, name='order_excel'),
    path('order-correction/', views.order_correction_view, name='order_correction'),
    path('dispatch/<str:batch_id>/', views.order_dispatch_view, name='order_dispatch'),
    path('order/delivered/<str:order_no>/', views.mark_delivered_view, name='mark_delivered'),
    path('inquiry/', views.order_inquiry_view, name='order_inquiry'),

    # Purchase Orders 
    path('purchase-order/make/', views.make_po_view, name='make_po'),
    path('purchase-order/confirm/', views.po_confirm_purchase_view, name='po_confirm_purchase'),
    path('purchase-order/approve/', views.approve_po_view, name='approve_po'),
    path('purchase-order/inquiry/', views.po_inquiry_view, name='po_inquiry'),
    path('purchase-order/correction/', views.po_correction_view, name='po_correction'),
    path('purchase-order/print/', views.print_po_view, name='print_po'),
    path('api/get-item-details/', views.api_get_item_details, name='api_get_item_details'),

    # Receiving / Inspection 
    path('receiving/receive/', views.ri_receive_view, name='receive_item'),
    path('receiving/delivery-request/', views.ri_delivery_request_view, name='delivery_request'),
    path('receiving/material-tag/', views.ri_material_tag_view, name='material_tag'),
    path('receiving/storage/', views.ri_storage_view, name='storage'),
    path('receiving/picking/', views.ri_picking_view, name='ri_picking'),
    path('receiving/picking/process-scan/', views.process_picking_scan, name='process_picking_scan'),
    path('receiving/movement-slip/<str:req_no>/', views.movement_slip_print_view, name='print_slip'),
    path('receiving/search-items/', views.search_items, name='search_items'),
    path('receiving/import-excel/', views.import_delivery_excel, name='import_excel'),
    path('receiving/get-po-details/', views.get_po_details, name='get_po_details'),
    path('receiving/material-tag/print/', views.material_tag_print_view, name='material_tag_print'),
    path('receiving/storage/get-stock/', views.get_location_stock, name='get_location_stock'),
    path('receiving/storage/transfer/', views.process_storage_transfer, name='process_storage_transfer'),
    path('receiving/picking-list-print/<str:req_no>/', views.picking_list_print_view, name='picking_list_print'),
    path('api/get-picking-list/', views.get_picking_list, name='get_picking_list'),
    path('api/get-po-for-tag/', views.get_po_for_tag, name='get_po_for_tag'),
    path('api/get-item-details/', views.get_item_details, name='get_item_details'),
    path('api/get-material-tag/', views.api_get_material_tag, name='api_get_material_tag'),
    path('api/update-tag-status/', views.api_update_tag_status, name='api_update_tag_status'),
    path('api/get-picking-list/', views.get_picking_list, name='api_get_picking_list'),

    # MATERIAL REQUEST MODULE
    path('request/new/', views.new_request_view, name='new_request'),
    path('request/my-list/', views.my_requests_view, name='my_requests'),
    path('request/return/', views.return_slip_view, name='return_slip'),

    # API para sa View Button
    path('api/request-details/<int:req_id>/', views.api_request_details, name='api_request_details'),    

    # INVENTORY PROCESSING MODULE
    path('processing/move/', views.stock_move_view, name='stock_move'),
    path('processing/correction/', views.stock_correction_view, name='stock_correction'),
    path('processing/out/', views.stock_out_view, name='stock_out'),
    path('processing/get-tag/', views.get_tag_info, name='get_tag_info'),
    path('inventory-request/get-tag/', views.get_tag_info, name='get_tag_info'),

    # INVENTORY INQUIRY MODULE
    path('inventory-inquiry/stock/', views.stock_inquiry_view, name='stock_inquiry'),
    path('inventory-inquiry/item/', views.stock_item_inquiry_view, name='stock_item_inquiry'),
    path('inventory-inquiry/history/', views.stock_history_view, name='stock_history'),
    path('inventory-inquiry/request/', views.request_inquiry_view, name='request_inquiry'),
    path('inventory-inquiry/settings/', views.inquiry_settings_view, name='inquiry_settings'),
    path('inventory-inquiry/stock-io/<int:tag_id>/', views.stock_io_view, name='stock_io_history'),
    
    # API
    path('api/update-item-price/', views.api_update_item_price, name='api_update_item_price'),

    # INBOUND & RECEIVING MODULE
    path('inbound/shipment-import/', views.shipment_import_view, name='shipment_import'),
    path('inbound/shipment-inquiry/', views.shipment_inquiry_view, name='shipment_inquiry'),
    path('inbound/shipping-confirmation/', views.shipping_confirmation_view, name='shipping_confirmation'),
    path('inbound/shipment-update/', views.shipment_update, name='shipment_update'),
    path('api/shipment-details/<int:ship_id>/', views.api_shipment_details, name='api_shipment_details'),
    path('inbound/shipment-allocation/<int:ship_id>/', views.shipment_allocation_view, name='shipment_allocation'),
    path('inbound/shipment-allocate/register/<int:ship_id>/', views.shipment_register_allocation, name='shipment_register_allocation'),
    path('inbound/shipment-invoice/<int:ship_id>/', views.shipment_invoice_view, name='shipment_invoice'),
    path('inbound/shipment-print/<int:ship_id>/', views.shipment_print_view, name='shipment_print'),

    path('master/locations/', views.location_master_view, name='location_master'),
    path('receive/scan/', views.receive_item_scan_view, name='receive_item_scan'), 
    path('receive/print/<int:tag_id>/', views.print_tag_view, name='print_tag'),

    # Assembly & Asset Management
    path('assembly/dashboard/', views.assembly_dashboard_view, name='assembly_dashboard'),
    path('assembly/machine/create/', views.machine_create_view, name='machine_create'),
    path('assembly/machine/<int:machine_id>/', views.machine_detail_view, name='machine_detail'),
    path('assembly/print-label/<int:log_id>/', views.print_assembly_label, name='print_assembly_label'),
    path('api/assembly/action/', views.api_assembly_action, name='api_assembly_action'),
    path('api/assembly/complete/', views.api_assembly_complete, name='api_assembly_complete'),

    # PASSWORD RESET PATHS
    path('reset_password/', auth_views.PasswordResetView.as_view(template_name='Inventory/auth/password_reset_form.html'), name='password_reset'),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name='Inventory/auth/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='Inventory/auth/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name='Inventory/auth/password_reset_complete.html'), name='password_reset_complete'),

    #email route management
    path('item/<int:item_id>/stock-out/', views.stock_out_item, name='stock_out_item'),
    path('master/email/', views.email_master_view, name='email_master'),
    path('master/email/update/', views.update_email_route, name='update_email_route'),
    path('system/scan-expiry/', views.trigger_expiry_scan, name='trigger_expiry_scan'),
    
    path('system-audit/', views.system_audit_logs_view, name='system_audit_logs'),


    path('system/test-email/', views.test_all_email_templates_view, name='test_email_system'),
]