from django.db import migrations


def create_ubuntu_group(apps, schema_editor):
    Group = apps.get_model("authentication", "Group")
    Group.objects.get_or_create(name="ubuntu", defaults={"server_tags": "ubuntu"})


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0006_activitylog_metadata_certificate_principals_and_more"),
    ]

    operations = [
        migrations.RunPython(create_ubuntu_group, migrations.RunPython.noop),
    ]
