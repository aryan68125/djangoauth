#here in this module we will be overriding the default from django.contrib.auth.tokens import PasswordResetTokenGenerator and rename it to TokenGenerator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class TokenGenerator(PasswordResetTokenGenerator):
    pass

generated_token = TokenGenerator()
