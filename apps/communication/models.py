from django.db import models

# Create your models here.


class Announcement(models.Model):
    id = models.AutoField(primary_key=True)
    teacher = models.ForeignKey('users.Teacher', on_delete=models.CASCADE, related_name='announcements')
    title = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} by {self.teacher.user.name}"


class Notification(models.Model):
    ACTION_CHOICES = [
        ('new_assignment', 'New Assignment'),
        ('assignment_graded', 'Assignment Graded'),
        ('new_announcement', 'New Announcement'),
        ('new_lecture', 'New Lecture'),
    ]
    TARGET_TYPE_CHOICES = [
        ('assignment', 'Assignment'),
        ('lecture', 'Lecture'),
        ('announcement', 'Announcement'),
    ]
    id = models.UUIDField(primary_key=True, editable=False)
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    body = models.JSONField(blank=True, null=True)
    action_type = models.CharField(max_length=50, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=50, choices=TARGET_TYPE_CHOICES)
    target_id = models.IntegerField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} for {self.user.name}"
