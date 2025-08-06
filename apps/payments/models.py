from django.db import models

# Create your models here.

class Payment(models.Model):
    id = models.AutoField(primary_key=True)
    student = models.ForeignKey('users.Student', on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50)
    transaction_id = models.CharField(max_length=100, unique=True)
    paid_at = models.DateTimeField()

    def __str__(self):
        return f"Payment {self.id} by {self.student.user.name} - {self.amount} ({self.status})"
