from datetime import timedelta
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from .models import ActivityLog, Certificate, CustomUser, Group, GroupIP, PublicKey
from .ssh_utils import SSHValidationError, validate_ssh_public_key

# Valid Ed25519 public key for test fixtures (test vector only, no matching private key).
SAMPLE_ED25519_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"
)


class SSHUtilsTests(TestCase):
    def test_valid_ed25519_key_returns_normalized_and_fingerprint(self):
        parsed = validate_ssh_public_key(SAMPLE_ED25519_PUBKEY)
        self.assertEqual(parsed.key_type, "ssh-ed25519")
        self.assertTrue(parsed.normalized_key.startswith("ssh-ed25519 "))
        self.assertTrue(parsed.fingerprint_sha256.startswith("SHA256:"))

    def test_rejects_multiline_or_options_injection(self):
        with self.assertRaises(SSHValidationError):
            validate_ssh_public_key(f"{SAMPLE_ED25519_PUBKEY}\nextra-line")
        with self.assertRaises(SSHValidationError):
            validate_ssh_public_key(f'command="id" {SAMPLE_ED25519_PUBKEY}')

    def test_rejects_unsupported_key_type(self):
        with self.assertRaises(SSHValidationError):
            validate_ssh_public_key("ssh-dss AAAAB3NzaC1kc3MAAACBAInvalid==")


@override_settings(
    ALLOW_SELF_REGISTRATION=True,
    REGISTRATION_INVITE_CODE="",
    ADMIN_BOOTSTRAP_TOKEN="test-admin-bootstrap",
    TAG_SYNC_TOKEN="test-tag-sync-token",
    CA_SIGNER_TOKEN="test-ca-signer-token",
    SSH_CERT_VALIDITY="+24h",
)
class AuthAndCertificateFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.devops_group = Group.objects.create(name="devops", server_tags="dev,prod")
        # 'ubuntu' is seeded automatically by migration 0007_seed_ubuntu_group.
        self.ubuntu_group = Group.objects.get(name="ubuntu")

    def test_registration_and_login_with_cookies_and_bearer(self):
        resp = self.client.post(
            "/api/register/",
            {
                "email": "alice@example.com",
                "username": "alice_1",
                "password": "StrongPassword!123",
                "group": "devops",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201)
        user = CustomUser.objects.get(email="alice@example.com")
        self.assertIn(self.devops_group, user.custom_groups.all())

        # Login without specifying group infers user's group and sets HttpOnly cookies
        login_resp = self.client.post(
            "/api/token/",
            {"email": "alice@example.com", "password": "StrongPassword!123"},
            format="json",
        )
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn("access", login_resp.data)
        self.assertEqual(login_resp.data["group"], "devops")
        self.assertIn("access_token", login_resp.cookies)
        self.assertTrue(login_resp.cookies["access_token"]["httponly"])

    def test_normal_register_cannot_join_ubuntu_admin_group(self):
        resp = self.client.post(
            "/api/register/",
            {
                "email": "attacker@example.com",
                "username": "attacker",
                "password": "StrongPassword!123",
                "group": "ubuntu",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    @override_settings(ALLOW_SELF_REGISTRATION=False)
    def test_self_registration_disabled_blocks_register_and_groups(self):
        self.assertEqual(self.client.get("/api/registration-groups/").status_code, 403)
        resp = self.client.post(
            "/api/register/",
            {
                "email": "bob@example.com",
                "username": "bob_1",
                "password": "StrongPassword!123",
                "group": "devops",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_bootstrap_and_json_login(self):
        # Missing bootstrap token fails
        bad_resp = self.client.post(
            "/api/admin/register/",
            {
                "email": "admin@example.com",
                "username": "rootadmin",
                "password": "StrongPassword!123",
            },
            format="json",
        )
        self.assertEqual(bad_resp.status_code, 403)

        ok_resp = self.client.post(
            "/api/admin/register/",
            {
                "email": "admin@example.com",
                "username": "rootadmin",
                "password": "StrongPassword!123",
            },
            format="json",
            HTTP_X_BOOTSTRAP_TOKEN="test-admin-bootstrap",
        )
        self.assertEqual(ok_resp.status_code, 201)

        login_resp = self.client.post(
            "/api/admin/login/",
            {"email": "admin@example.com", "password": "StrongPassword!123"},
            format="json",
        )
        self.assertEqual(login_resp.status_code, 200)
        self.assertEqual(login_resp.data["group"], "ubuntu")

        # Admin can create new groups via POST /api/groups/, regular users cannot
        admin_user = CustomUser.objects.get(email="admin@example.com")
        self.client.force_authenticate(user=admin_user)
        user_info = self.client.get("/api/get-user/").json()
        self.assertTrue(user_info["is_admin"])

        grp_resp = self.client.post(
            "/api/groups/",
            {"name": "qa_team", "server_tags": "qa"},
            format="json",
        )
        self.assertEqual(grp_resp.status_code, 201)
        self.assertTrue(Group.objects.filter(name="qa_team").exists())

        regular = CustomUser.objects.create_user(
            email="norm@example.com",
            username="norm_user",
            password="StrongPassword!123",
            group=self.devops_group,
        )
        self.client.force_authenticate(user=regular)
        self.assertEqual(
            self.client.post("/api/groups/", {"name": "sre"}, format="json").status_code,
            403,
        )

    def test_receive_tags_requires_service_token_and_validates_ip(self):
        unauth = self.client.post(
            "/api/receive-tags/",
            {"tags": ["qa"], "public_ip": "10.0.0.5"},
            format="json",
        )
        self.assertEqual(unauth.status_code, 401)

        bad_ip = self.client.post(
            "/api/receive-tags/",
            {"tags": ["qa"], "public_ip": "not-an-ip"},
            format="json",
            HTTP_X_SERVICE_TOKEN="test-tag-sync-token",
        )
        self.assertEqual(bad_ip.status_code, 400)

        ok = self.client.post(
            "/api/receive-tags/",
            {"tags": ["qa"], "public_ip": "10.0.0.5"},
            format="json",
            HTTP_X_SERVICE_TOKEN="test-tag-sync-token",
        )
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(GroupIP.objects.filter(group_name="qa", public_ip="10.0.0.5").count(), 1)

        # Duplicate IP does not create duplicate row
        self.client.post(
            "/api/receive-tags/",
            {"tags": ["qa"], "public_ip": "10.0.0.5"},
            format="json",
            HTTP_X_SERVICE_TOKEN="test-tag-sync-token",
        )
        self.assertEqual(GroupIP.objects.filter(group_name="qa", public_ip="10.0.0.5").count(), 1)

    @patch("authentication.views.request_certificate_signature")
    def test_pubkey_sign_and_revoke_flow(self, mock_sign):
        user = CustomUser.objects.create_user(
            email="dev@example.com",
            username="dev_user",
            password="StrongPassword!123",
            group=self.devops_group,
        )
        self.client.force_authenticate(user=user)

        # Invalid key rejected
        bad_key = self.client.post("/api/pub-key/", {"key": "not-a-key"}, format="json")
        self.assertEqual(bad_key.status_code, 400)

        # Valid key accepted
        good_key = self.client.post("/api/pub-key/", {"key": SAMPLE_ED25519_PUBKEY}, format="json")
        self.assertEqual(good_key.status_code, 201)
        self.assertEqual(PublicKey.objects.filter(user=user, signed=False).count(), 1)

        # GET /api/keysign/ is rejected (must be POST)
        self.assertEqual(self.client.get("/api/keysign/").status_code, 405)

        valid_until = timezone.now() + timedelta(hours=24)
        mock_sign.return_value = {
            "certificate": "ssh-ed25519-cert-v01@openssh.com MOCKCERT",
            "serial": 123456,
            "valid_until_dt": valid_until,
            "fingerprint": "SHA256:mock",
        }

        sign_resp = self.client.post("/api/keysign/", {}, format="json")
        self.assertEqual(sign_resp.status_code, 200)
        self.assertIn("MOCKCERT", sign_resp.content.decode("utf-8"))

        cert = Certificate.objects.get(user=user)
        self.assertEqual(cert.serial, 123456)
        self.assertEqual(cert.principals, "devops")
        self.assertFalse(cert.revoked)

        # Second active sign attempt blocked
        self.client.post("/api/pub-key/", {"key": SAMPLE_ED25519_PUBKEY}, format="json")
        blocked_resp = self.client.post("/api/keysign/", {}, format="json")
        self.assertEqual(blocked_resp.status_code, 403)

        # Revoke certificate and verify re-signing becomes allowed
        revoke_resp = self.client.post(f"/api/certificates/{cert.id}/revoke/", {}, format="json")
        self.assertEqual(revoke_resp.status_code, 200)
        cert.refresh_from_db()
        self.assertTrue(cert.revoked)
        self.assertIsNotNone(cert.revoked_at)

        # ActivityLog entries recorded cleanly
        events = set(ActivityLog.objects.filter(user=user).values_list("event", flat=True))
        self.assertTrue({"public_key_uploaded", "certificate_issued", "certificate_revoked"}.issubset(events))

        resign_resp = self.client.post("/api/keysign/", {}, format="json")
        self.assertEqual(resign_resp.status_code, 200)

    @patch("authentication.views.check_ca_signer_health", return_value=True)
    def test_healthz_endpoint(self, _mock_health):
        resp = self.client.get("/api/healthz/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")


class CASignerIntegrationTests(TestCase):
    def test_real_ssh_keygen_signing_with_signer_module(self):
        repo_root = Path(__file__).resolve().parents[2]
        signer_path = repo_root / "ca-signer" / "signer.py"
        sign_script = repo_root / "sign.sh"
        if not signer_path.exists() or not sign_script.exists():
            self.skipTest("ca-signer files not present")

        with tempfile.TemporaryDirectory() as tmpdir:
            ca_key = os.path.join(tmpdir, "ca_key")
            user_key = os.path.join(tmpdir, "user_key")
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", ca_key, "-N", "", "-q"],
                check=True,
            )
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", user_key, "-N", "", "-q"],
                check=True,
            )
            with open(f"{user_key}.pub", "r", encoding="utf-8") as fh:
                user_pub = fh.read().strip()

            spec = importlib.util.spec_from_file_location("ca_signer", signer_path)
            signer = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(signer)

            orig_ca = signer.CA_KEY_PATH
            orig_script = signer.SIGN_SCRIPT
            try:
                os.environ["CA_KEY_PATH"] = ca_key
                signer.CA_KEY_PATH = ca_key
                signer.SIGN_SCRIPT = str(sign_script)

                result = signer.sign_public_key(
                    {
                        "public_key": user_pub,
                        "identity": "alice@example.com",
                        "principals": ["devops"],
                        "validity": "+1h",
                        "serial": 42,
                    }
                )
                self.assertIn("ssh-ed25519-cert-v01@openssh.com", result["certificate"])
                self.assertEqual(result["serial"], 42)
                self.assertIsNotNone(result["valid_to"])

                with self.assertRaises(ValueError):
                    signer.sign_public_key(
                        {
                            "public_key": user_pub,
                            "identity": "alice@example.com",
                            "principals": ["devops; rm -rf /"],
                            "validity": "+1h",
                        }
                    )
            finally:
                os.environ.pop("CA_KEY_PATH", None)
                signer.CA_KEY_PATH = orig_ca
                signer.SIGN_SCRIPT = orig_script
