import jwt, uuid
from datetime import datetime, timedelta, timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import SignupSerializer, LoginSerializer, UserSerializer, StudentSerializer
from .models import User, Student

def _cfg(): return getattr(settings, "JWT_SETTINGS", {})
def _now(): return datetime.now(timezone.utc)

def _encode_long_lived_token(user_id: int):
    cfg = _cfg()
    exp = _now() + timedelta(days=cfg.get("ACCESS_TTL_DAYS", 30))
    payload = {
        "sub": str(user_id),
        "type": "access",     
        "iat": int(_now().timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=cfg.get("ALGORITHM", "HS256"))
    return token

def _decode(token: str):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[_cfg().get("ALGORITHM","HS256")])

def _get_user_from_bearer(request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, Response({"detail": "Authorization header missing or invalid."}, status=401)
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = _decode(token)
    except jwt.ExpiredSignatureError:
        return None, Response({"detail": "Token expired."}, status=401)
    except jwt.InvalidTokenError:
        return None, Response({"detail": "Invalid token."}, status=401)

    try:
        user = User.objects.get(id=int(payload["sub"]))
    except (User.DoesNotExist, ValueError):
        return None, Response({"detail": "User not found."}, status=401)
    return user, None

class SignupView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        s = SignupSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.save()
        token = _encode_long_lived_token(user.id)
        return Response({"user": UserSerializer(user).data, "token": token}, status=201)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.validated_data["user"]
        token = _encode_long_lived_token(user.id)  
        return Response({"user": UserSerializer(user).data, "token": token}, status=200)

class LogoutView(APIView):
    def post(self, request):
        return Response({"detail": "Logged out."}, status=200)

class MeView(APIView):
    def get(self, request):
        user, err = _get_user_from_bearer(request)
        if err: return err
        data = {"user": UserSerializer(user).data}
        try:
            student = Student.objects.get(pk=user.id)
            data["student"] = StudentSerializer(student).data
        except Student.DoesNotExist:
            data["student"] = None
        return Response(data, status=200)
