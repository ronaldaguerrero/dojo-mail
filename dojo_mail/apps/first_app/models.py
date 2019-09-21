from django.db import models

# Create your models here.
class User(models.Model):
  first_name = models.CharField(max_length=45)
  last_name = models.CharField(max_length=45)
  # username = models.CharField(max_length=45)
  # timezone = models.CharField(max_length=255, default = "PST Pacific Standard Time California UTC 08:00")
  email = models.CharField(max_length=255)
  # backup_email = models.CharField(max_length=255)
  password = models.CharField(max_length=255)
  message_forwarding = models.BooleanField(default=False)
  forward_to_email = models.CharField(max_length=255, blank=True)
  # spam = models.ListCharField(
  #       base_field=CharField(max_length=255)


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
  deleted = models.BooleanField(default=False)
  user = models.ForeignKey(User, related_name='emails', on_delete=models.PROTECT)

# Validator example:
# # Create your models here.
# class ShowManager(models.Manager):
#   def validator(self, postData):
#     d = dt.strptime(postData['rel_date'], "%Y-%m-%d")
#     today = dt.now()
#     errors = {}
#     if len(postData['title']) < 2:
#       errors["title"] = "Title should be at least 2 characters"
#     if len(postData['net']) < 3:
#       errors["network"] = "Network should be at least 3 characters"
#     if len(postData['desc']) < 10:
#       if len(postData['desc']) < 1:
#         pass
#       elif len(postData['desc']) < 10:
#         errors["description"] = "Descrption should be at least 10 characters"
#     if d > today:
#       errors["release_date"] = 'Release date should be in the past'
#     title = Show.objects.filter(title=postData['title'])
#     if len(title) > 0:
#       errors['title'] = 'Title is taken'
#     return errors

# class Show(models.Model):
#   title = models.CharField(max_length=255)
#   network = models.CharField(max_length=255)
#   release_date = models.DateField()
#   description = models.TextField()
#   created_at = models.DateTimeField(auto_now=True)
#   updated_at = models.DateTimeField(auto_now_add=True)
#   objects = ShowManager()