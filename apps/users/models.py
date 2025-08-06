from django.db import models

class User(models.Model):
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
    ]
    id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    name = models.CharField(max_length=255)
    profile_photo = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email


class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    level = models.ForeignKey('learning.Level', on_delete=models.SET_NULL, null=True, blank=True)
    placement_score = models.IntegerField()
    subscription_status = models.BooleanField(default=False)
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"Student: {self.user.name}"


class Teacher(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    bio = models.TextField(blank=True, null=True)
    office_hours = models.CharField(max_length=255, blank=True, null=True)
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"Teacher: {self.user.name}"
