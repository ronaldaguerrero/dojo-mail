from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

import re	# the regex module
# create a regular expression object that we'll use later   
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

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
        new_user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=password_hash)
        request.session['user_email'] = request.POST['email']
        request.session['user_id'] = User.objects.last().id
        print('='*50)
        print('created a new user', new_user.__dict__)
        return redirect('/success')

def login(request):
    users_with_email = User.objects.filter(email=request.POST['email'])
    if len(users_with_email) > 0:
        enteredPassword = request.POST['password']
        existingpw = users_with_email[0].password
        check = bcrypt.checkpw(enteredPassword.encode(),existingpw.encode())
        if (check == True):
            request.session['user_id'] = users_with_email[0].id
            request.session['user_email'] = request.POST['email']
            return redirect('/success')
        else:
            messages.error(request, "Invalid Login Info")
            return redirect('/register')
    else:
        messages.error(request, "Invalid Login Info")
        return redirect('/register')

def success(request):
    user = User.objects.get(id=request.session['user_id'])
    context = {
        'user': user,
    }
    return render(request, 'first_app/success.html', context)

def logout(request):
    request.session['user_id'] = None
    request.session['user_email'] = None
    messages.error(request, "You have logged out")
    return redirect('/register')

def send_email(request):
	this_user = User.objects.get(id=request.session['user_id'])
	e = Email(subject = request.POST['subject'], message=request.POST['message'], from_email=request.session['user_email'], to_email=request.POST['to-email'], user=this_user)
	e.save()	
	return redirect('/success', context=[])

def view_emails(request):
	view_emails = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=False)
	inbox_count = Email.objects.all().filter(to_email=request.session['user_email']).count()
	sent_count = Email.objects.all().filter(from_email=request.session['user_email']).count()
	deleted_count = Email.objects.all().filter(to_email=request.session['user_email']).filter(deleted=True).count()
	context = {
		'view_emails': view_emails,
		'inbox_count': inbox_count,
		'sent_count' : sent_count,
		'deleted_count' : deleted_count
	}
	return render(request,'first_app/show.html', context=context)

# Login pseudocode
# 1. Query database for a user with the email address entered
# 2. If the user exists, use the bcrypt.checkpw function in order to check hashed password
# 3. If the function returns true, then add the user's id to request.session
# 4. redirect