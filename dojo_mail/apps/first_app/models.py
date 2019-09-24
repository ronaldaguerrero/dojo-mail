from django.db import models

# Create your models here.
class User(models.Model):
  first_name = models.CharField(max_length=45)
  last_name = models.CharField(max_length=45)
  # username = models.CharField(max_length=45)
  # timezone = models.CharField(max_length=255, default = "PST Pacific Standard Time California UTC 08:00")
  email = models.CharField(max_length=255)
  backup_email = models.CharField(max_length=255, blank=True)
  password = models.CharField(max_length=255)
  message_forwarding = models.BooleanField(default=False)
  forward_to_email = models.CharField(max_length=255, blank=True)
  spam = models.TextField(blank=True)

class Email(models.Model):
  subject = models.CharField(max_length=255, blank=True, null=True)
  message = models.TextField()
  from_email = models.CharField(max_length=255)
  to_email = models.CharField(max_length=255)
  # to_email = models.ListCharField(
  #       base_field=CharField(max_length=255)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)
  read = models.BooleanField(default=False)
  spam = models.BooleanField(default=False)
  deleted = models.BooleanField(default=False)
  user = models.ForeignKey(User, related_name='emails', on_delete=models.PROTECT)

# # Validator example:
# # Create your models here.
# class EmailManager(models.Manager):
#   def validator(self, postData):
#     errors = {}
#     to_email = User.objects.filter(email=postData['to-email'])
#     print('hello from email validator')
#     print(to_email)
#     if len(postData['to-email']) < 1:
#       errors["to-email"] = "'To email' must be present"
#     if len(postData['message']) < 1:
#         errors["description"] = "Message should be at least 2 characters"
#     return errors

# class Show(models.Model):
#   title = models.CharField(max_length=255)
#   network = models.CharField(max_length=255)
#   release_date = models.DateField()
#   description = models.TextField()
#   created_at = models.DateTimeField(auto_now=True)
#   updated_at = models.DateTimeField(auto_now_add=True)
#   objects = ShowManager()