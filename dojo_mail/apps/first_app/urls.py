from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^test$', views.test),
    url(r'^$', views.register_form),
    url(r'^register$', views.register_form),
    url(r'^users$', views.register_user),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),
    url(r'^compose$', views.compose),
    url(r'^send_email$', views.send_email),
    url(r'^view_emails$', views.view_emails),
    url(r'^sent_emails$', views.sent_emails),
    url(r'^spam_emails$', views.spam_emails),
    url(r'^deleted_emails$', views.deleted_emails),
    url(r'^view_email/(?P<value>\d+)$', views.view_email),
    url(r'^reply/(?P<value>\d+)$', views.reply),
    url(r'^delete/(?P<value>\d+)$', views.delete),
    url(r'^search$', views.search),
    url(r'^fwd$', views.fwd),
    url(r'^message_fwd$', views.message_fwd),
    url(r'^spam/(?P<value>\d+)$', views.spam),
]