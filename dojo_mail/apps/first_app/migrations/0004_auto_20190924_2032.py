# Generated by Django 2.2.5 on 2019-09-25 03:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('first_app', '0003_user_backup_email'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='backup_email',
            new_name='timezone',
        ),
    ]
