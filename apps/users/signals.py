# """
# Django signals for the users app.
# """

# from django.db.models.signals import post_save, post_delete
# from django.dispatch import receiver
# from django.contrib.auth import get_user_model

# from .models import UserProfile
# from .tasks import (
#     send_verification_email_task,
#     send_welcome_email_task,
#     create_user_profile_task,
# )

# User = get_user_model()


# @receiver(post_save, sender=User)
# def create_user_profile(sender, instance, created, **kwargs):
#     """
#     Create user profile when a new user is created.
#     """
#     if created:
#         # Create profile asynchronously
#         create_user_profile_task.delay(instance.id)

#         # Send welcome email asynchronously
#         send_welcome_email_task.delay(instance.id)

#         # Send verification email asynchronously
#         send_verification_email_task.delay(instance.id)


# @receiver(post_save, sender=User)
# def update_user_profile(sender, instance, created, **kwargs):
#     """
#     Update user profile when user is updated.
#     """
#     if not created:
#         try:
#             # Update profile based on user changes
#             # For example, update learning level if it changed
#             instance.profile
#         except UserProfile.DoesNotExist:
#             # Create profile if it doesn't exist
#             create_user_profile_task.delay(instance.id)


# @receiver(post_save, sender=UserProfile)
# def update_user_learning_level(sender, instance, created, **kwargs):
#     """
#     Update user's learning level based on profile statistics.
#     """
#     from .utils import calculate_user_level

#     if not created:
#         # Calculate new level based on progress
#         new_level = calculate_user_level(
#             instance.lessons_completed,
#             instance.exercises_completed
#         )

#         # Update user's learning level if it changed
#         if instance.user.learning_level != new_level:
#             instance.user.learning_level = new_level
#             instance.user.save(update_fields=['learning_level'])


# @receiver(post_delete, sender=User)
# def cleanup_user_data(sender, instance, **kwargs):
#     """
#     Clean up user-related data when user is deleted.
#     """
#     # This signal can be used to clean up related data
#     # For example, delete user's study sessions, progress records, etc.
#     pass