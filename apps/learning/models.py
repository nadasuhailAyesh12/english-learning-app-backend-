from django.db import models
# Create your models here.

class Level(models.Model):
    LEVEL_CHOICES = [
        ('beginner', 'Beginner'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced'),
    ]
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=20, choices=LEVEL_CHOICES)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class Lecture(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    video_url = models.URLField(blank=True, null=True)
    pdf_url = models.URLField(blank=True, null=True)
    level = models.ForeignKey(Level, on_delete=models.SET_NULL, null=True, blank=True)
    teacher = models.ForeignKey('users.Teacher', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class Assignment(models.Model):
    id = models.AutoField(primary_key=True)
    lecture = models.ForeignKey(Lecture, on_delete=models.CASCADE, related_name='assignments')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    due_date = models.DateField()
    file_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class Submission(models.Model):
    id = models.AutoField(primary_key=True)
    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE, related_name='submissions')
    student = models.ForeignKey('users.Student', on_delete=models.CASCADE, related_name='submissions')
    file_url = models.URLField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    grade = models.FloatField(null=True, blank=True)
    teacher_feedback = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Submission by {self.student.user.name} for {self.assignment.title}"
