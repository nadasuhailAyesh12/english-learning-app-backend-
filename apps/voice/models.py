from django.db import models

# Create your models here.

class VoiceSession(models.Model):
    SESSION_TYPE_CHOICES = [
        ('group', 'Group'),
        ('one_on_one', 'One-on-One'),
    ]
    SESSION_STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed'),
    ]
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=20, choices=SESSION_TYPE_CHOICES)
    host = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='hosted_voice_sessions')
    scheduled_at = models.DateTimeField()
    status = models.CharField(max_length=20, choices=SESSION_STATUS_CHOICES)

    def __str__(self):
        return f"{self.type} session by {self.host.name} at {self.scheduled_at}"


class SessionParticipant(models.Model):
    session = models.ForeignKey(VoiceSession, on_delete=models.CASCADE, related_name='participants')
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='voice_sessions')

    class Meta:
        unique_together = ('session', 'user')

    def __str__(self):
        return f"{self.user.name} in session {self.session.id}"
