from locust import HttpUser, between, task
import random
import string


def random_email():
    return f"user{random.randint(1000, 99999)}@example.com"


def random_username():
    return "user_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


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
        response = self.client.post(
            "/api/register/",
            json={
                "username": self.username,
                "email": self.email,
                "password": self.password,
                "group": self.user_group,
            },
        )
        if response.status_code != 201:
            print(f"Registration failed: {response.status_code} - {response.text}")

    def login(self):
        response = self.client.post(
            "/api/token/",
            json={
                "email": self.email,
                "password": self.password,
                "group": self.user_group,
            },
        )
        if response.status_code == 200:
            self.token = response.json()["access"]
            self.refresh = response.json()["refresh"]
            self.client.headers["Authorization"] = f"Bearer {self.token}"
        else:
            print(f"Login failed: {response.status_code} - {response.text}")

    @task
    def pub_key(self):
        pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        self.client.post("/api/pub-key/", json={"key": pubkey})

    @task
    def keysign(self):
        self.client.post("/api/keysign/", json={})

    @task
    def get_user(self):
        self.client.get("/api/get-user/")

    @task
    def get_all_certs(self):
        self.client.get("/api/certificates/")
