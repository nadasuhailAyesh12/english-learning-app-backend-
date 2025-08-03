"""
Utility functions for the users app.
"""

import secrets
import string
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string


def generate_verification_token(length=32):
    """
    Generate a secure verification token for email verification.

    Args:
        length (int): Length of the token

    Returns:
        str: Secure random token
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def send_verification_email(user, token):
    """
    Send email verification email to user.

    Args:
        user: User instance
        token (str): Verification token

    Returns:
        bool: True if email sent successfully
    """
    subject = 'Verify your email address'

    # Create verification URL
    verification_url = f"{settings.SITE_URL}/verify-email/{token}/"

    context = {
        'user': user,
        'verification_url': verification_url,
    }

    # Render email templates
    html_message = render_to_string('users/emails/verify_email.html', context)
    plain_message = render_to_string('users/emails/verify_email.txt', context)

    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        # Log the error in production
        print(f"Failed to send verification email: {e}")
        return False


def send_welcome_email(user):
    """
    Send welcome email to newly registered user.

    Args:
        user: User instance

    Returns:
        bool: True if email sent successfully
    """
    subject = 'Welcome to English Learning App!'

    context = {
        'user': user,
    }

    html_message = render_to_string('users/emails/welcome.html', context)
    plain_message = render_to_string('users/emails/welcome.txt', context)

    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send welcome email: {e}")
        return False


def calculate_user_level(lessons_completed, exercises_completed):
    """
    Calculate user's learning level based on progress.

    Args:
        lessons_completed (int): Number of completed lessons
        exercises_completed (int): Number of completed exercises

    Returns:
        str: User's calculated level
    """
    total_progress = lessons_completed + (exercises_completed * 0.1)

    if total_progress < 10:
        return 'beginner'
    elif total_progress < 50:
        return 'intermediate'
    else:
        return 'advanced'

