# Generated by Django 2.2.4 on 2019-09-19 18:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('first_app', '0008_auto_20190919_0814'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='forward_to_email',
            field=models.CharField(default=2, max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='message_forwarding',
            field=models.BooleanField(default=False),
        ),
    ]
