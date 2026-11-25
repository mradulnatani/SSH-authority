from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import ActivityLog, Certificate, CustomUser, Group, GroupIP, PublicKey


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ("email", "username", "group", "is_admin_user", "is_staff", "is_active")
    list_filter = ("is_admin_user", "is_staff", "is_active", "group")
    search_fields = ("email", "username")
    ordering = ("email",)
    fieldsets = UserAdmin.fieldsets + (
        ("SSH Authority", {"fields": ("group", "is_admin_user")}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ("SSH Authority", {"fields": ("email", "group", "is_admin_user")}),
    )


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ("name", "server_tags")
    search_fields = ("name", "server_tags")


@admin.register(PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "key_type", "fingerprint", "signed", "uploaded_at")
    list_filter = ("signed", "key_type")
    search_fields = ("user__email", "fingerprint")


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "group", "serial", "principals", "issued_at", "valid_until", "revoked")
    list_filter = ("revoked", "group")
    search_fields = ("id", "user__email", "principals")
    readonly_fields = ("id", "issued_at")


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "event")
    list_filter = ("event",)
    search_fields = ("user__email", "event")
    readonly_fields = ("timestamp",)


@admin.register(GroupIP)
class GroupIPAdmin(admin.ModelAdmin):
    list_display = ("group_name", "public_ip", "group")
    list_filter = ("group_name",)
    search_fields = ("group_name", "public_ip")
