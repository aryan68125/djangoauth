from django.shortcuts import render, redirect
'''this is a inbuilt django Views class that handles the remdering of views that are built in to the django web framework'''
from django.views.generic import View

'''import messages app that is built in the django web framework'''
from django.contrib import messages

'''install validate-email module before importing it type pip3 install validate-email in your terminal to install the module'''
from validate_email import validate_email

from django.contrib.auth.models import User
'''
construct a url that is unique to the application that we've built so we need the the current domain that our application is running on
and we will set it dynamically we can import this:- from django.contrib.sites.shortcuts import get_current_site
'''
from django.contrib.sites.shortcuts import get_current_site

#now redirect user to the login page
# so inorder to do that you need to import :- from django.template.loader import render_to_string this library renders a template with a context automatically
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from . utils import generated_token
from django.core.mail import EmailMessage
from django.conf import settings

# Create your views here.
class Home(View):
    #to handle the get request
    #to handle the get request
    def get(self, request):
        return render(request, 'auth/home.html')
    def post(self, request):
        return redirect('register')

class RegistrationView(View):
    #to handle the get request
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        #now we need to go back to the template register otherwise we won't be able to create th user in the database
        data = request.POST,
        stuff_for_frontend = {

              'data' : data,
              'has_error':False,

        }

        #now check if the passwords are provided
        password = request.POST.get('password')
        if len(password)<6:
            messages.add_message(request,messages.ERROR, 'Password should be atleast 6 characters long')
            stuff_for_frontend['has_error'] = True

        #now we need to validate the email address entered by the user so inorder to do that we need to install validate-email module from pip repository
        #type pip3 install validate-email in your terminal
        email = request.POST.get('email')
        #now check if the email address is valid or not
        if not validate_email(email):
            messages.add_message(request,messages.ERROR, 'Email not valid!')
            stuff_for_frontend['has_error'] = True

        #check if the email is taken
        #to find out if the user exsists or not in our database if yes then return user name taken use .exists() function to do the job
        if User.objects.filter(email=email).exists():
            messages.add_message(request,messages.ERROR, 'Email is taken')
            stuff_for_frontend['has_error'] = True
        #now check if there is any error in the user input
        username = request.POST.get('username')
        if User.objects.filter(username=username).exists():
            messages.add_message(request,messages.ERROR, 'Username is taken')
            stuff_for_frontend['has_error'] = True

        print(data)
        if stuff_for_frontend['has_error']:
            return render(request, 'auth/register.html', stuff_for_frontend, status=400) #here if we set status to 400 that meands we can prevent the user profile from being created in the database if the error is generated if any of our test condition fails


        #now create the user in the database
        user = User.objects.create_user(username=username, email=email)
        #now set the password for that user and store it in the database
        user.set_password(password)
        #set active user to false so that they don't accidentally get logged in before the email verification process is complete
        user.is_active=False
        #now save the user
        user.save() # now we can say that the user account is successfully created
        #now add a message informing the user that their account has been created successfully
        messages.add_message(request,messages.SUCCESS, 'Account is created successfully')

        #send the verification link to the user's email address
        #step1. construct a url that is unique to the application that we've built so we need the the current domain that our application is running on
        #       and we will set it dynamically we can import this:- from django.contrib.sites.shortcuts import get_current_site
        current_site = get_current_site(request) #get_current_site(request) will give us the current domain of our website dinamically
        #step2. create an email subject
        email_subject= 'Email verification'

        #step3. construct a message
        # so inorder to do that you need to import :- from django.template.loader import render_to_string this library renders a template with a context automatically
        #convert the user.pk into bytes so we need to import:- from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
        #import a module that generated a unique token for our application when we need to verify the user's email address :- from django.contrib.auth.tokens import PasswordResetTokenGenerator it can be used to activate accounts and to reset password
        create_a_context_for_front_end={
            'user':user,
            'domain':current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generated_token.make_token(user),
        }
        message = render_to_string('auth/activate.html',create_a_context_for_front_end)
        #step4. send an email for authentation of the account import :- from django.core.mail import EmailMessage and import settings :- from django.conf import settings
        '''
        email_message = EmailMessage(
           email_subject,            #subject of the email
           message,                  #message that you want to send via email
           settings.EMAIL_HOST_USER, #EMAIL_HOST = 'smtp.gmail.com' that is being imported from the settings.py of the django project
           [email],                  #email adderess entered by the user in the regitration form in the front end of the application of the django project
        )
        '''
        email_message = EmailMessage(
           email_subject,
           message,
           settings.EMAIL_HOST_USER,
           [email],
        )
        email_message.send()
        #now redirect user to the login page
        return redirect('login')

class ActivateAccountView(View):
    def get(self, request,uidb64,token):
        print(f"request = {request}")
        #in here we will check if the token is valid or not
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            print(f"uid = {uid}")
            user = User.objects.get(pk=uid)
            print(f"user = {user}")
        except User.DoesNotExist:
            user = None

        #now check the user before activating them
        if user is not None and generated_token.check_token(user,token):
            print(f"token = {token}")
            #now activate the user in the database for operational ready i.e user now have the permission to use the web Application
            user.is_active = True
            ptrint(f"user active stauts = {user.is_active}")
            user.save()
            messages.add_message(request,messages.INFO,'account activated successfully')
            return redirect('login')
        return render(request,'auth/error.html', status=401)

class LoginView(View):
    #now get request
    def get(self, request):
        return render(request, 'auth/login.html')
