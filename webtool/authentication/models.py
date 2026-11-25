from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
import uuid


PRINCIPAL_NAME_VALIDATOR = RegexValidator(
    regex=r"^[a-zA-Z_][a-zA-Z0-9._-]{0,63}$",
    message="Group/principal name must start with a letter or underscore and contain only letters, digits, '.', '_', or '-'.",
)


class Group(models.Model):
    """Access group whose name maps to an SSH certificate principal."""

    name = models.CharField(max_length=100, unique=True, validators=[PRINCIPAL_NAME_VALIDATOR])
    server_tags = models.TextField(help_text="Comma-separated tags like dev, qa, prod")
    users = models.ManyToManyField("CustomUser", related_name="custom_groups", blank=True)

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    """Application user authenticating via email and scoped to a group/role."""

    email = models.EmailField(unique=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    is_admin_user = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return self.email

    def clean(self):
        super().clean()
        if self.group_id is not None and self.group.name == "ubuntu":
            other_users = CustomUser.objects.filter(group__name="ubuntu").exclude(pk=self.pk)
            if other_users.exists():
                raise ValidationError("Only one user can be assigned to the 'ubuntu' group.")
        elif self.is_admin_user and not self.is_superuser:
            raise ValidationError("Only the user in the 'ubuntu' group can be an admin.")

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)
        if self.group_id is not None:
            self.custom_groups.add(self.group)


class PublicKey(models.Model):
    """Validated SSH public key uploaded by a user."""

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="public_keys")
    key_data = models.TextField()
    key_type = models.CharField(max_length=64, blank=True, default="")
    fingerprint = models.CharField(max_length=128, blank=True, default="")
    signed = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Public Key ({self.key_type or 'unknown'}) for {self.user.email}"


class Certificate(models.Model):
    """Issued OpenSSH user certificate metadata and PEM/OpenSSH payload."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="certificates")
    public_key = models.ForeignKey(PublicKey, on_delete=models.SET_NULL, null=True, related_name="certificates")
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, related_name="certificates")
    serial = models.BigIntegerField(null=True, blank=True)
    principals = models.CharField(max_length=255, blank=True, default="")
    issued_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()
    cert_data = models.TextField()
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Cert {self.id} for {self.user.email}"


class ActivityLog(models.Model):
    """Audit trail for authentication, key submission, issuance, and revocation events."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    event = models.CharField(max_length=255)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        actor = self.user.email if self.user else "system"
        return f"{actor} - {self.event}"


class GroupIP(models.Model):
    """Public IP addresses of servers mapped to an access group."""

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="ips", null=True, blank=True)
    group_name = models.CharField(max_length=100)
    public_ip = models.GenericIPAddressField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["group_name", "public_ip"], name="unique_group_ip")
        ]

    def __str__(self):
        return f"{self.group_name} -> {self.public_ip}"
