"""
Admin interface for user models.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User, UserProfile


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin interface for User model."""

    list_display = [
        'email', 'first_name', 'last_name', 'learning_level',
        'email_verified', 'is_staff', 'is_active', 'created_at'
    ]
    list_filter = [
        'learning_level', 'email_verified', 'is_staff',
        'is_active', 'created_at'
    ]
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['-created_at']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {
            'fields': (
                'first_name', 'last_name', 'date_of_birth',
                'profile_picture'
            )
        }),
        (_('Learning info'), {
            'fields': ('native_language', 'learning_level')
        }),
        (_('Permissions'), {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            )
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        (_('Email verification'), {
            'fields': ('email_verified', 'email_verification_token')
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'first_name', 'last_name', 'password1',
                'password2', 'learning_level'
            ),
        }),
    )


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model."""

    list_display = [
        'user', 'lessons_completed', 'exercises_completed',
        'current_streak', 'longest_streak', 'daily_goal_minutes'
    ]
    list_filter = ['created_at', 'notifications_enabled']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    ordering = ['-created_at']

    fieldsets = (
        (None, {'fields': ('user',)}),
        (_('Learning Statistics'), {
            'fields': (
                'total_study_time', 'lessons_completed',
                'exercises_completed', 'current_streak', 'longest_streak'
            )
        }),
        (_('Preferences'), {
            'fields': (
                'daily_goal_minutes', 'notifications_enabled',
                'email_notifications'
            )
        }),
        (_('Timestamps'), {'fields': ('created_at', 'updated_at')}),
    )

    readonly_fields = ['created_at', 'updated_at']