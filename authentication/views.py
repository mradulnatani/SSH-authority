from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from google.oauth2 import service_account
from googleapiclient.discovery import build
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE_ACCOUNT_FILE = os.path.join(BASE_DIR, 'authentication', 'credentials', 'certificate-authority-457820-eb5fe6b623b7.json')

ADMIN_EMAIL = 'django-directory-access@certificate-authority-457820.iam.gserviceaccount.com'
SCOPES = ['https://www.googleapis.com/auth/admin.directory.group.readonly']

from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    """Logs out the user and redirects to the login page."""
    logout(request)
    return redirect('index')  


def index(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'authentication/index.html')


@login_required
def dashboard(request):
    user_email = request.user.email
    groups = get_user_groups(user_email)
    return render(request, "authentication/dashboard.html", {"user_groups": groups})


@login_required
def role_form(request):
    if not request.user.is_authenticated:
        return redirect('index')

    user_email = request.user.email
    user_groups = get_user_groups(user_email)
    print(f"[DEBUG] user_groups in role_form: {user_groups}")

    if request.method == "POST":
        selected_role = request.POST.get("role")
        if selected_role in user_groups:
            request.session['selected_role'] = selected_role
            return redirect('dashboard')
        else:
            return HttpResponse("You are not authorized for this role.", status=403)

    return render(request, "authentication/role_form.html", {"group_roles": user_groups})


@login_required
def upload_key(request):
    user_email = request.user.email
    user_groups = get_user_groups(user_email)
    selected_role = request.session.get("selected_role")  # ✅ use session-stored role

    if not selected_role or selected_role not in user_groups:
        return HttpResponse("You are not authorized for this role.", status=403)

    if request.method == "POST":
        ssh_key = request.POST.get("ssh_key")
        if not ssh_key:
            return HttpResponse("SSH Key is required.", status=400)

        # TODO: Save SSH key + selected_role to DB
        return HttpResponse("SSH Key saved successfully!")

    return render(request, "authentication/upload_key.html", {
        "group_roles": user_groups, 
        "selected_role": selected_role  # to show in the template
    })



@login_required
def activity_log(request):
    # TODO: Fetch logs and cert validity from DB
    dummy_data = {
        "cert_validity": "2025-05-12",
        "recent_actions": [
            {"time": "2025-04-30", "action": "SSH key added"},
            {"time": "2025-05-01", "action": "Cert issued"},
        ],
    }
    return render(request, "authentication/activity_log.html", dummy_data)


@login_required
def ssh_access(request):
    # TODO: Determine IPs based on user's roles
    allowed_ips = ["192.168.0.101", "192.168.0.202"]
    return render(request, "authentication/ssh_access.html", {"ips": allowed_ips})


def get_user_groups(user_email):
    try:
        credentials = (
            service_account.Credentials.from_service_account_file(
                SERVICE_ACCOUNT_FILE, scopes=SCOPES
            ).with_subject(ADMIN_EMAIL)
        )
        service = build('admin', 'directory_v1', credentials=credentials)
        response = service.groups().list(userKey=user_email).execute()

        print("[DEBUG] Raw response from Google API:", response)

        groups = [group['email'] for group in response.get('groups', [])]
        print("[DEBUG] Extracted group emails:", groups)
        return groups

    except Exception as e:
        print(f"[ERROR] Failed to fetch groups for {user_email}: {e}")
        return []
