"""
Celery tasks for the users app.
"""

# from celery import shared_task
# from django.core.mail import send_mail
# from django.conf import settings
# from django.template.loader import render_to_string

# from .models import User, UserProfile
# from .utils import generate_verification_token, send_welcome_email


# @shared_task



# @shared_task
# def send_welcome_email_task(user_id):
#     """
#     Send welcome email as a background task.

#     Args:
#         user_id (int): User ID
#     """
#     try:
#         user = User.objects.get(id=user_id)
#         success = send_welcome_email(user)

#         if success:
#             return f"Welcome email sent to {user.email}"
#         else:
#             return f"Failed to send welcome email to {user.email}"

#     except User.DoesNotExist:
#         return f"User with ID {user_id} not found"
#     except Exception as e:
#         return f"Error sending welcome email: {str(e)}"





# @shared_task
# def send_password_reset_email_task(user_id, reset_token):
#     """
#     Send password reset email as a background task.

#     Args:
#         user_id (int): User ID
#         reset_token (str): Password reset token
#     """
#     try:
#         user = User.objects.get(id=user_id)

#         subject = 'Reset your password'
#         reset_url = f"{settings.SITE_URL}/reset-password/{reset_token}/"

        # context = {
        #     'user': user,
        #     'reset_url': reset_url,
        # }

        # html_message = render_to_string('users/emails/password_reset.html', context)
        # plain_message = render_to_string('users/emails/password_reset.txt', context)

        # send_mail(
        #     subject=subject,
        #     message=plain_message,
        #     from_email=settings.DEFAULT_FROM_EMAIL,
        #     recipient_list=[user.email],
        #     html_message=html_message,
        #     fail_silently=False,
        # )

    #     return f"Password reset email sent to {user.email}"

    # except User.DoesNotExist:
    #     return f"User with ID {user_id} not found"
    # except Exception as e:
    #     return f"Error sending password reset email: {str(e)}"


