"""
Tests for user views and API endpoints.
"""

import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.models import UserProfile

User = get_user_model()


class UserViewSetTest(APITestCase):
    """Test cases for UserViewSet."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'testpass123',
            'password_confirm': 'testpass123',
            'learning_level': 'beginner',
            'native_language': 'Spanish'
        }

        self.user = User.objects.create_user(
            email='existing@example.com',
            first_name='Jane',
            last_name='Doe',
            password='testpass123'
        )

    def test_create_user_success(self):
        """Test successful user creation."""
        url = reverse('user-list')
        response = self.client.post(url, self.user_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)

        user = User.objects.get(email=self.user_data['email'])
        self.assertEqual(user.first_name, self.user_data['first_name'])
        self.assertEqual(user.last_name, self.user_data['last_name'])
        self.assertEqual(user.learning_level, self.user_data['learning_level'])

    def test_create_user_missing_fields(self):
        """Test user creation with missing required fields."""
        url = reverse('user-list')

        # Test without email
        data = self.user_data.copy()
        del data['email']
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Test without password
        data = self.user_data.copy()
        del data['password']
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_user_password_mismatch(self):
        """Test user creation with password mismatch."""
        url = reverse('user-list')
        data = self.user_data.copy()
        data['password_confirm'] = 'differentpassword'

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_create_user_duplicate_email(self):
        """Test user creation with duplicate email."""
        url = reverse('user-list')
        data = self.user_data.copy()
        data['email'] = self.user.email

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_user_list_authenticated(self):
        """Test getting user list when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return the authenticated user
        self.assertEqual(len(response.data['results']), 1)

    def test_get_user_list_unauthenticated(self):
        """Test getting user list when not authenticated."""
        url = reverse('user-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_user_detail_authenticated(self):
        """Test getting user detail when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-detail', kwargs={'pk': self.user.pk})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)

    def test_get_user_detail_unauthenticated(self):
        """Test getting user detail when not authenticated."""
        url = reverse('user-detail', kwargs={'pk': self.user.pk})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_me_endpoint(self):
        """Test the 'me' endpoint."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-me')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['first_name'], self.user.first_name)

    def test_update_profile_authenticated(self):
        """Test updating user profile when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-update-profile')
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'learning_level': 'intermediate'
        }

        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.learning_level, 'intermediate')

    def test_change_password_authenticated(self):
        """Test changing password when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-change-password')
        data = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
            'new_password_confirm': 'newpass123'
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpass123'))

    def test_change_password_wrong_old_password(self):
        """Test changing password with wrong old password."""
        self.client.force_authenticate(user=self.user)
        url = reverse('user-change-password')
        data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpass123',
            'new_password_confirm': 'newpass123'
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)


class UserProfileViewSetTest(APITestCase):
    """Test cases for UserProfileViewSet."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='John',
            last_name='Doe',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(user=self.user)

    def test_get_profile_list_authenticated(self):
        """Test getting profile list when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('profile-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_get_profile_list_unauthenticated(self):
        """Test getting profile list when not authenticated."""
        url = reverse('profile-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_profile_detail_authenticated(self):
        """Test getting profile detail when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('profile-detail', kwargs={'pk': self.profile.pk})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['email'], self.user.email)

    def test_create_profile_authenticated(self):
        """Test creating profile when authenticated."""
        # Delete existing profile
        self.profile.delete()

        self.client.force_authenticate(user=self.user)
        url = reverse('profile-list')
        data = {
            'daily_goal_minutes': 45,
            'notifications_enabled': False
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(profile.daily_goal_minutes, 45)
        self.assertFalse(profile.notifications_enabled)

    def test_update_profile_authenticated(self):
        """Test updating profile when authenticated."""
        self.client.force_authenticate(user=self.user)
        url = reverse('profile-detail', kwargs={'pk': self.profile.pk})
        data = {
            'daily_goal_minutes': 60,
            'email_notifications': False
        }

        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.daily_goal_minutes, 60)
        self.assertFalse(self.profile.email_notifications)

    def test_get_statistics_endpoint(self):
        """Test the statistics endpoint."""
        self.client.force_authenticate(user=self.user)
        url = reverse('profile-statistics')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_study_time', response.data)
        self.assertIn('lessons_completed', response.data)
        self.assertIn('exercises_completed', response.data)
        self.assertIn('current_streak', response.data)
        self.assertIn('longest_streak', response.data)
        self.assertIn('daily_goal_minutes', response.data)


@pytest.mark.django_db
class UserViewsPytestTest:
    """Pytest-style tests for user views."""

    def test_user_creation_api(self, api_client):
        """Test user creation via API."""
        url = '/api/v1/users/'
        data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'testpass123',
            'password_confirm': 'testpass123',
            'learning_level': 'beginner'
        }

        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email=data['email']).exists()

    def test_user_authentication(self, api_client, user_factory):
        """Test user authentication."""
        user = user_factory()
        url = '/api/v1/auth/token/'
        data = {
            'email': user.email,
            'password': 'testpass123'
        }

        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data