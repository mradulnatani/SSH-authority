from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.index, name='index'),  # This is your login page , my dumbass added base.html as login
    path('dashboard/', views.dashboard, name='dashboard'),
    path('role-form/', views.role_form, name='role_form'),  # Add the role form route , pehle kuch aur likha tha isilye didnt work
    path('upload-key/', views.upload_key, name='upload_key'),
    path('activity-log/', views.activity_log, name='activity_log'),
    path('ssh-access/', views.ssh_access, name='ssh_access'),
    path('logout/', views.logout_view, name='logout')
]