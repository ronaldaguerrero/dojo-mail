# Generated by Django 2.2.4 on 2019-09-18 21:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('first_app', '0002_auto_20190918_1213'),
    ]

    operations = [
        migrations.AlterField(
            model_name='email',
            name='from_email',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='email',
            name='to_email',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(max_length=255),
        ),
    ]