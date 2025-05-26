from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid

# -------------------------
# 1. Custom User Model
# -------------------------

class CustomUser(AbstractUser):  
    email = models.EmailField(unique=True)
    group = models.ForeignKey('Group', on_delete=models.CASCADE)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'group']  # include group here

    def __str__(self):
        return self.email

# -------------------------
# 2. Group Model
# -------------------------

class Group(models.Model):
    name = models.CharField(max_length=100, unique=True)
    server_tags = models.TextField(help_text="Comma-separated tags like dev, qa, prod")

    def __str__(self):
        return self.name


# -------------------------
# 3. Public Key Model
# -------------------------

class PublicKey(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='public_keys')
    key_data = models.TextField()
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Public Key for {self.user.email}"


# -------------------------
# 4. Certificate Model
# -------------------------

class Certificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='certificates')
    public_key = models.ForeignKey(PublicKey, on_delete=models.SET_NULL, null=True, related_name='certificates')
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, related_name='certificates')
    issued_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()
    cert_data = models.TextField()

    def __str__(self):
        return f"Cert {self.id} for {self.user.email}"

