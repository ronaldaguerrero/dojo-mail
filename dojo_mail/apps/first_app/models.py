from django.db import models

# Create your models here.
class User(models.Model):
  first_name = models.CharField(max_length=45)
  last_name = models.CharField(max_length=45)
  username = models.CharField(max_length=45)
  # timezone
  email = models.CharField(max_length=255)
  backup_email = models.CharField(max_length=255)
  password = models.CharField(max_length=255)

class Email(models.Model):
  subject = models.CharField(max_length=255, blank=True, null=True)
  message = models.TextField()
  from_email = models.CharField(max_length=255)
  to_email = models.CharField(max_length=255)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  read = models.BooleanField(null=False)
  deleted = models.BooleanField(null=False)
  user = models.ForeignKey(User, related_name='emails', on_delete=models.PROTECT)
