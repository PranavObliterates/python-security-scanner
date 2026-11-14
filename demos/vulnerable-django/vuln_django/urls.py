from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('user', views.get_user, name='get_user'),
    path('search', views.search, name='search'),
    path('ssti', views.ssti_demo, name='ssti'),
    path('pickle', views.pickle_demo, name='pickle'),
]
