from django.urls import path,include

from . import views

urlpatterns =[
    path("",views.index, name="index"),
    path("home/", views.home, name="home"),
    path("role-form/", views.role_form, name="role_form"),


]