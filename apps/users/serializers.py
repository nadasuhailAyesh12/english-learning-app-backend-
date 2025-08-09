from rest_framework import serializers
from django.contrib.auth.hashers import make_password, check_password
from .models import User, Student

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "role", "name", "profile_photo", "created_at"]

class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = ["level", "placement_score", "subscription_status", "is_available"]

class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6, write_only=True)
    name = serializers.CharField(max_length=255)
    profile_photo = serializers.URLField(required=False, allow_blank=True, allow_null=True)

    def validate_email(self, v):
        if User.objects.filter(email__iexact=v).exists():
            raise serializers.ValidationError("Email already in use.")
        return v

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data["email"].lower(),
            password_hash=make_password(validated_data["password"]),
            role="student",
            name=validated_data["name"],
            profile_photo=validated_data.get("profile_photo"),
        )
        Student.objects.create(user=user)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs["email"].lower()
        password = attrs["password"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")
        if not check_password(password, user.password_hash):
            raise serializers.ValidationError("Invalid email or password.")
        attrs["user"] = user
        return attrs


