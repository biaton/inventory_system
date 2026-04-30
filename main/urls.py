from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView 

urlpatterns = [
    path('admin/', admin.site.urls),
    # Lahat ng request ay ipapasa natin sa Inventory app
    path('', include('Inventory.urls')), 
    path('', RedirectView.as_view(pattern_name='login', permanent=False), name='root'),
]

# Ibinalik natin ito pero TANGGAL na ang debug_toolbar para gumana ang mga pictures at colors!
if settings.DEBUG:
    # Static at Media files (Para lumabas ang AIM-LOGO.jpg, CSS, at iba pa)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)