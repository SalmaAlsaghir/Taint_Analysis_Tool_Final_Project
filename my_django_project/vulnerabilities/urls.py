from django.urls import path
from . import views

urlpatterns = [
    path('xss/', views.xss_vulnerability, name='xss'),
    path('sql/', views.sql_injection, name='sql'),
]
