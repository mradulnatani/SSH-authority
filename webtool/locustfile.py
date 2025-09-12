from locust import HttpUser, task, between
import random
import string
import json

def random_email():
    return f"user{random.randint(1000,9999)}@example.com"

def random_username():
    return "user_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

class SSHCertAuthorityUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.username = random_username()
        self.email = random_email()
        self.password = "TestPass123!"
        self.user_group = "testing"

        self.client.headers = {"Content-Type": "application/json"}
        self.register()
        self.login()

    def register(self):
        response = self.client.post("/api/register/", json={
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "group": self.user_group
        })
        if response.status_code != 201:
            print(f"Registration failed: {response.status_code} - {response.text}")

    def login(self):
        response = self.client.post("/api/token/", json={
            "username": self.username,
            "password": self.password
        })
        if response.status_code == 200:
            self.token = response.json()["access"]
            self.client.headers["Authorization"] = f"Bearer {self.token}"
        else:
            print(f"Login failed: {response.status_code} - {response.text}")


    @task
    def pub_key(self):
        pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
        self.client.post("/api/pub-key/", json={"public_key": pubkey})

    @task
    def keysign(self):
        pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
        self.client.post("/api/keysign/", json={"public_key": pubkey})

    @task
    def get_user(self):
        self.client.get("/api/get-user/")

    @task
    def get_all_certs(self):
        self.client.get("/api/certificates/")

    @task
    def logout(self):
        self.client.post("/api/logout/")

class AdminUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        self.username = "admin_" + random_username()
        self.email = random_email()
        self.password = "AdminPass123!"
        self.user_group = "testing"

        self.client.headers = {"Content-Type": "application/json"}
        self.register()
        self.login()

    def register(self):
        response = self.client.post("/api/admin/register/", json={
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "group": self.user_group
        })
        if response.status_code != 201:
            print(f"Admin Registration failed: {response.status_code} - {response.text}")

    def login(self):
        response = self.client.post("/api/admin/login/", json={
            "username": self.username,
            "password": self.password
        })
        if response.status_code == 200:
            self.token = response.json()["access"]
            self.client.headers["Authorization"] = f"Bearer {self.token}"
        else:
            print(f"Admin Login failed: {response.status_code} - {response.text}")

    @task
    def get_groups(self):
        self.client.get("/api/groups/")

    @task
    def get_group_ips(self):
        self.client.get("/api/group-ips/")

    @task
    def get_all_certs(self):
        self.client.get("/api/certificates/")

