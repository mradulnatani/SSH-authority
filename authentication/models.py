from django.db import models
from django.contrib.auth.models import User

# Group (like a Google Group)
class Group(models.Model):
    name = models.CharField(max_length=150, unique=True)   # e.g. 'dev-team'
    description = models.TextField(blank=True)
    parent_group = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subgroups'
    )  # For hierarchy (subteams)
    all_members_ssh_access = models.BooleanField(default=False)  # If all members get SSH access
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# Role (access roles like dev, frontend)
class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)  # e.g. 'developer'
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# Users linked to groups (simulate Google Groups membership)
class UserGroup(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    is_verified = models.BooleanField(default=False)  # Verified by admin or self
    has_ssh_access = models.BooleanField(default=False)  # SSH access flag
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'group')

    def __str__(self):
        return f"{self.user.email} in {self.group.name}"


# Group-Roles mapping: which roles belong to which groups
class GroupRole(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('group', 'role')

    def __str__(self):
        return f"{self.role.name} in {self.group.name}"


# Public keys uploaded by users
class PublicKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    fingerprint = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Key for {self.user.email} ({self.fingerprint})"


# Certificates issued to users
class Certificate(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.ForeignKey(PublicKey, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    serial_number = models.CharField(max_length=100, unique=True)
    certificate_data = models.BinaryField()  # Store actual cert bytes
    issued_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Cert #{self.serial_number} for {self.user.email}"


# Server tags (like "dev", "prod", "frontend")
class ServerTag(models.Model):
    tag_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.tag_name


# Which role can access which server tag and at what level (read/write etc.)
class RoleTagPermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    tag = models.ForeignKey(ServerTag, on_delete=models.CASCADE)
    access_level = models.CharField(max_length=50)  # e.g. 'read', 'write', 'admin'
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('role', 'tag')

    def __str__(self):
        return f"{self.role.name} -> {self.tag.tag_name} ({self.access_level})"


# Audit logs for security and tracking
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('CERT_ISSUED', 'Certificate Issued'),
        ('KEY_UPLOADED', 'SSH Key Uploaded'),
        ('ACCESS_DENIED', 'Access Denied'),
        # Add more as needed
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    certificate = models.ForeignKey(Certificate, on_delete=models.SET_NULL, null=True, blank=True)
    action_type = models.CharField(max_length=50, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    server_tag = models.CharField(max_length=100, blank=True)  # Server or environment tag
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    def __str__(self):
        return f"{self.user.email} - {self.action_type} at {self.timestamp}"

