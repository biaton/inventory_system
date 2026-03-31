from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView 

urlpatterns = [
    path('admin/', admin.site.urls),
    # Lahat ng request ay ipapasa natin sa Inventory app
    path('', include('Inventory.urls')), 
    path('', RedirectView.as_view(pattern_name='login', permanent=False), name='root'),
]