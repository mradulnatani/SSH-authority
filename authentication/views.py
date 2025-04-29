from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from google.oauth2 import service_account
from googleapiclient.discovery import build

SERVICE_ACCOUNT_FILE = 'path/to/your/service-account.json'
ADMIN_EMAIL = 'admin@yourdomain.com'  # Must be a super admin in the same Workspace domain
SCOPES = ['https://www.googleapis.com/auth/admin.directory.group.readonly']


def index(request):
    return render(request, 'authentication/index.html')

def home(request):
    return HttpResponse("This is the homepage.")


def get_user_groups(user_email):
    try:
        credentials = (
            service_account.Credentials.from_service_account_file(
                SERVICE_ACCOUNT_FILE, scopes=SCOPES
            ).with_subject(ADMIN_EMAIL)
        )

        service = build('admin', 'directory_v1', credentials=credentials)
        response = service.groups().list(userKey=user_email).execute()
        return [group['email'] for group in response.get('groups', [])]

    except Exception as e:
        print(f"Error fetching Google groups: {e}")
        return []


@login_required
def role_form(request):
    user_email = request.user.email
    user_groups = get_user_groups(user_email)

    if request.method == "POST":
        selected_role = request.POST.get("role")
        ssh_key = request.POST.get("ssh_key")

        if selected_role not in user_groups:
            return HttpResponse("You are not authorized for this role.", status=403)

        # Here, you would save the SSH key and role in your database
        return HttpResponse(f"Role: {selected_role}, SSH Key Saved!")

    return render(request, "authentication/role_form.html", {
        "group_roles": user_groups
    })
