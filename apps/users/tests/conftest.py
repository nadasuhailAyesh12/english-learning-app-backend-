"""
Pytest configuration and fixtures for users app tests.
"""

# import pytest
# from django.contrib.auth import get_user_model
# from rest_framework.test import APIClient
# from factory import Faker
# from factory.django import DjangoModelFactory

# from apps.users.models import UserProfile

# User = get_user_model()


# class UserFactory(DjangoModelFactory):
#     """Factory for creating User instances."""

#     class Meta:
#         model = User

#     email = Faker('email')
#     first_name = Faker('first_name')
#     last_name = Faker('last_name')
#     learning_level = Faker('random_element', elements=['beginner', 'intermediate', 'advanced'])
#     native_language = Faker('random_element', elements=['English', 'Spanish', 'French', 'German'])

#     @classmethod
#     def _create(cls, model_class, *args, **kwargs):
#         """Create user with password."""
#         password = kwargs.pop('password', 'testpass123')
#         user = super()._create(model_class, *args, **kwargs)
#         user.set_password(password)
#         user.save()
#         return user


# class UserProfileFactory(DjangoModelFactory):
#     """Factory for creating UserProfile instances."""

#     class Meta:
#         model = UserProfile

#     user = None  # Will be set by the factory
#     daily_goal_minutes = Faker('random_int', min=15, max=120)
#     notifications_enabled = Faker('boolean')
#     email_notifications = Faker('boolean')


# @pytest.fixture
# def user_factory():
#     """Fixture for UserFactory."""
#     return UserFactory


# @pytest.fixture
# def user_profile_factory():
#     """Fixture for UserProfileFactory."""
#     return UserProfileFactory


# @pytest.fixture
# def api_client():
#     """Fixture for API client."""
#     return APIClient()


# @pytest.fixture
# def authenticated_client(api_client, user_factory):
#     """Fixture for authenticated API client."""
#     user = user_factory()
#     api_client.force_authenticate(user=user)
#     return api_client


# @pytest.fixture
# def user_with_profile(user_factory, user_profile_factory):
#     """Fixture for user with profile."""
#     user = user_factory()
#     profile = user_profile_factory(user=user)
#     return user, profile


# @pytest.fixture
# def admin_user(user_factory):
#     """Fixture for admin user."""
#     return user_factory(is_staff=True, is_superuser=True)


# @pytest.fixture
# def verified_user(user_factory):
#     """Fixture for verified user."""
#     return user_factory(email_verified=True)


# @pytest.fixture
# def unverified_user(user_factory):
#     """Fixture for unverified user."""
#     return user_factory(email_verified=False)


# @pytest.fixture
# def beginner_user(user_factory):
#     """Fixture for beginner user."""
#     return user_factory(learning_level='beginner')


# @pytest.fixture
# def intermediate_user(user_factory):
#     """Fixture for intermediate user."""
#     return user_factory(learning_level='intermediate')


# @pytest.fixture
# def advanced_user(user_factory):
#     """Fixture for advanced user."""
#     return user_factory(learning_level='advanced')


# @pytest.fixture
# def user_data():
#     """Fixture for user creation data."""
#     return {
#         'email': 'test@example.com',
#         'first_name': 'John',
#         'last_name': 'Doe',
#         'password': 'testpass123',
#         'password_confirm': 'testpass123',
#         'learning_level': 'beginner',
#         'native_language': 'Spanish'
#     }


# @pytest.fixture
# def profile_data():
#     """Fixture for profile creation data."""
#     return {
#         'daily_goal_minutes': 45,
#         'notifications_enabled': True,
#         'email_notifications': False
#     }


# @pytest.fixture
# def password_change_data():
#     """Fixture for password change data."""
#     return {
#         'old_password': 'testpass123',
#         'new_password': 'newpass123',
#         'new_password_confirm': 'newpass123'
#     }


# @pytest.fixture
# def mock_send_mail(monkeypatch):
#     """Fixture for mocking send_mail function."""
#     def mock_send_mail(*args, **kwargs):
#         return 1  # Success

#     monkeypatch.setattr('django.core.mail.send_mail', mock_send_mail)
#     return mock_send_mail


# @pytest.fixture
# def mock_render_to_string(monkeypatch):
#     """Fixture for mocking render_to_string function."""
#     def mock_render_to_string(template_name, context):
#         return f"Mocked content for {template_name}"

#     monkeypatch.setattr('django.template.loader.render_to_string', mock_render_to_string)
#     return mock_render_to_string