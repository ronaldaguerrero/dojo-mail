from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import  Q
from .models import *
import bcrypt

import re	# the regex module
# create a regular expression object that we'll use later   
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

def test(request):
	return render(request, 'first_app/login_reg.html')

def register_form(request):
	return render(request, 'first_app/index.html')

def register_user(request):
	# 1. Validate the form inputs
	errors = {}
	if len(request.POST['first_name'])<2:
		errors['first_name'] = "First name must be at least two characters long"
	if request.POST['first_name'].isalpha() == False:
		errors['first_name'] = "First name must have only letters"
	if len(request.POST['last_name'])<2:
		errors['last_name'] = "Last name must be at least two characters long"
	if request.POST['last_name'].isalpha() == False:
		errors['last_name'] = "Last name must have only letters"
	# These validations are new!! VVVVVVVVVVVVVV
	users_with_email = User.objects.filter(email=request.POST['email'])
	if len(users_with_email) > 0:
		errors['email'] = "Email is taken"
	if not EMAIL_REGEX.match(request.POST['email']):
		errors['email'] = "Email is invalid format."
	if len(request.POST['password'])< 8:
		errors['password'] = "Password must be at least 8 characters long"
	if request.POST['password'] != request.POST['confirm_password']:
		errors['password'] = "Password must match password confirmation"
	if len(errors) != 0:
		for key, value in errors.items():
			messages.error(request,value)
		return redirect('/register')
	else:
	# 2. If valid, hash the password with bcrypt
		# 2019-09: added 'utf8' in encode
		hash1 = bcrypt.hashpw(request.POST['password'].encode('utf8'), bcrypt.gensalt())
		# 2019-09: decoded
		password_hash = hash1.decode('utf8')
		# 3. Run the query to add the user to the db
		new_user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=password_hash, timezone=request.POST['timezone'])
		request.session['user_email'] = request.POST['email']
		request.session['user_id'] = User.objects.last().id
		return redirect('/compose')

def login(request):
	users_with_email = User.objects.filter(email=request.POST['email'])
	if len(users_with_email) > 0:
		enteredPassword = request.POST['password']
		existingpw = users_with_email[0].password
		check = bcrypt.checkpw(enteredPassword.encode(),existingpw.encode())
		if (check == True):
			request.session['user_id'] = users_with_email[0].id
			request.session['user_email'] = request.POST['email']
			return redirect('/compose')
		else:
			messages.error(request, "Invalid Login Info")
			return redirect('/register')
	else:
		messages.error(request, "Invalid Login Info")
		return redirect('/register')

def compose(request):
	user = User.objects.get(id=request.session['user_id'])
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	context = {
		'user': user,
		'view_email': view_email,
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request, 'first_app/compose.html', context)

def logout(request):
	request.session['user_id'] = None
	request.session['user_email'] = None
	messages.error(request, "You have logged out")
	return redirect('/register')

def send_email(request):
	errors = emailvalidator(request.POST)
	if len(errors) != 0:
		for key, value in errors.items():
			messages.error(request,value)
			print(errors)
		return redirect('/view_emails')
	else:
		# loop through list
		emails = request.POST['to-email']
		email_contents = emails.split(',')
		# loop through all users to all users in list
		for to_email in email_contents:
			to_email = to_email.strip()
			this_user = User.objects.get(id=request.session['user_id'])
			# check if 'to email' has activated fwd
			to_user = User.objects.get(email = to_email)
			if to_user.message_forwarding == True and to_user not in email_contents:
				# if fwd email address is not in list, add to list
				email_contents.append(to_user.forward_to_email)
			# check if to user has spam values
			if len(to_user.spam) > 0:
				spam_contents = to_user.spam.split(',')
				for spam in spam_contents:
					print(spam)
					if this_user.email == spam:
						e.spam = True
						e.save()
			# send email
			e = Email(subject = request.POST['subject'], message=request.POST['message'], from_email=request.session['user_email'], to_email=to_email, user=this_user)
			e.save()
		return redirect('/compose', context=[])

def emailvalidator(postData):
	errors = {}
	emails = postData['to-email']
	email_contents = emails.split(',')
	# loop through all users to all users in list
	for to_email in email_contents:
		try:
			user = User.objects.get(email = to_email) 
		except User.DoesNotExist:
			errors["to-email"] = "'To email' does not exist"
			return errors
	if len(postData['message']) < 1:
		errors["message"] = "Message should be at least 2 characters"
	return errors

def reply(request, value):
	user = User.objects.get(id=request.session['user_id'])
	email = Email.objects.get(pk=value)
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()	
	context = {
		'user': user,
		'view_email': email,
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request, 'first_app/reply.html', context)

def view_emails(request):
	user = User.objects.get(id=request.session['user_id'])
	view_emails = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=False).filter(spam=False).order_by('id')
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	
	paginator = Paginator(view_emails, 3) # set pagintation to 3
	page = request.GET.get('page')
	emails = paginator.get_page(page)
	
	context = {
		'user': user,
		'emails' : emails, 
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request,'first_app/show.html', context)

def sent_emails(request):
	user = User.objects.get(id=request.session['user_id'])
	sent_emails = Email.objects.all().filter(from_email=request.session['user_email']).filter(deleted=False).filter(spam=False).order_by('id')
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	
	paginator = Paginator(sent_emails, 3) # set pagintation to 3
	page = request.GET.get('page')
	emails = paginator.get_page(page)
	
	context = {
		'user': user,
		'emails' : emails, 
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request,'first_app/sent.html', context)

def spam_emails(request):
	user = User.objects.get(id=request.session['user_id'])
	spam_emails = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=False).filter(spam=True).order_by('id')
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	
	paginator = Paginator(spam_emails, 3) # set pagintation to 3
	page = request.GET.get('page')
	emails = paginator.get_page(page)
	
	context = {
		'user': user,
		'emails' : emails, 
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request,'first_app/spam.html', context)

def deleted_emails(request):
	user = User.objects.get(id=request.session['user_id'])
	deleted_emails = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).order_by('id')
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	
	paginator = Paginator(deleted_emails, 3) # set pagintation to 3
	page = request.GET.get('page')
	emails = paginator.get_page(page)
	
	context = {
		'user': user,
		'emails' : emails, 
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request,'first_app/spam.html', context)

def view_email(request, value):
	user = user = User.objects.get(id=request.session['user_id'])
	view_email = Email.objects.get(pk=value)
	view_email.read = True
	view_email.save()
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	context = {
		'user': user,
		'view_email': view_email,
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request, 'first_app/show_email.html', context)

def delete(request, value):
	email = Email.objects.get(pk=value)
	email.deleted = True;
	email.save()
	return redirect('/view_emails')

def fwd(request):
	user = user = User.objects.get(id=request.session['user_id'])
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	context = {
		'user': user,
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
		}
	return render(request,'first_app/fwd.html', context)

def message_fwd(request):
	errors = {}
	try:
		user = User.objects.get(email = request.POST['fwd_email']) 
	except User.DoesNotExist:
		errors["to-email"] = "'Forwarding Email' does not exist"
		for key, value in errors.items():
			messages.error(request,value)
		return redirect('/compose')
	if request.POST['message_fwd'] == "1":
		this_user = User.objects.get(pk=request.session['user_id'])		
		this_user.message_forwarding = True
		this_user.forward_to_email = request.POST['fwd_email']
		this_user.save()
	else:
		this_user = User.objects.get(pk=request.session['user_id'])
		this_user.message_forwarding = False
		this_user.forward_to_email = ""
		this_user.save()
	return redirect('/view_emails')

def spam(request, value):
	this_user = User.objects.get(pk=request.session['user_id'])
	spam_user = Email.objects.get(pk=value).from_email
	spam_email = Email.objects.get(pk=value)
	spam_email.spam = True
	spam_email.save()
	if spam_user not in this_user.spam:
		this_user.spam += spam_user + ","
		this_user.save()
	return redirect('/view_emails')

def search(request):
	unread_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(read=False).filter(spam=False).count()
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=False).count()
	spam_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(spam=True).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()

	all_results = Email.objects.filter(message__icontains=request.POST['query']).filter(to_email=request.session['user_email'])
	
	if len(all_results) == 0:
		results = "No Results"
		show = False
	else:	
		results = all_results
		show = True

	context = {
		'show': show,
		'results': results,
		'unread_count': unread_count,
		'inbox_count': inbox_count,
		'spam_count': spam_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request, 'first_app/result.html', context)
	# else:
	# 	return render(request, 'first_app/result.html')

# Login pseudocode
# 1. Query database for a user with the email address entered
# 2. If the user exists, use the bcrypt.checkpw function in order to check hashed password
# 3. If the function returns true, then add the user's id to request.session
# 4. redirect