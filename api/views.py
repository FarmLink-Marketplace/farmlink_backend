from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _
from .utils import ResetPassword_key
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.template.loader import get_template
import resend
from .serializers import RegisterSerializer, LoginSerializer


from .models import PasswordReset_keys, User


@swagger_auto_schema(
    method="post",
    request_body=RegisterSerializer,
    operation_summary="Register a new user",
    operation_description="Creates a user and initializes their profile.",
    tags=["Auth"],
)
@api_view(["POST"])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"message": "User registered successfully."}, status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method="post",
    request_body=LoginSerializer,
    operation_summary="Login user",
    operation_description="Returns access and refresh tokens for a valid user.",
    tags=["Auth"],
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if check_password(password, user.password):
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user_id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                }
            )
        else:
            return Response(
                {"erro": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method="post",
    operation_summary="Logout a user",
    operation_description="Logs out the authenticated user by blacklisting their refresh token.",
    tags=["Auth"],
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=["refresh"],
        properties={
            "refresh": openapi.Schema(
                type=openapi.TYPE_STRING,
                description="User's refresh token to be blacklisted",
            ),
        },
    ),
    responses={
        205: openapi.Response(
            description="LogOut Successful",
            examples={"application/json": {"detail": "LogOut Successful"}},
        ),
        400: openapi.Response(
            description="LogOut Unsuccessful",
            examples={
                "application/json": {"success": "fail", "detail": "LogOut UnSuccessful"}
            },
        ),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    """Logs a user out of the platform"""
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response(
            {"success": "fail", "detail": "Refresh token is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response(
            {"detail": "LogOut Successful"}, status=status.HTTP_205_RESET_CONTENT
        )
    except Exception as e:
        return Response(
            {"error": "fail", "detail": f"TokenError: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )


@swagger_auto_schema(
    method="post",
    operation_summary="Request Password Reset",
    operation_description="Accepts an email, checks if it exists in the database, and sends a reset link containing a UID and token.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "email": openapi.Schema(type=openapi.TYPE_STRING, format="email"),
        },
        required=["email"],
    ),
    responses={
        201: openapi.Response(
            description="Password reset link generated",
            examples={
                "application/json": {"detail": {"uid": "some-uid", "key": "some-key"}}
            },
        ),
        400: openapi.Response(
            description="Request failed",
            examples={"application/json": {"errors": "Something went wrong!"}},
        ),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    """
    Receives Email
    Check if Email is in database
    Send (uid, token) in a url
    """
    data = request.data
    if data and "email" in data:
        result = ResetPassword_key(email=data["email"])
        if not result:
            return Response(
                {"errors": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        key, uid = result
        user = get_object_or_404(User, email=data["email"])
        exp = timezone.now() + timezone.timedelta(hours=1)

        # Load and render the HTML email
        template = get_template("password_reset/password_reset.html")
        context = {
            "user": user,
            "key": key,
            "uid": uid,
            "expiry_date": exp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        html = template.render(context)

        # Build params for Resend
        params: resend.Emails.SendParams = {
            "from": "Scuibai <Admin@scuib.com>",
            "to": [user.email],
            "subject": "Reset Your Password",
            "html": html,
        }

        try:
            r = resend.Emails.send(params)
        except Exception as e:
            return Response(
                {"errors": f"Failed to send email: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"detail": "Password reset link sent to email."},
            status=status.HTTP_200_OK,
        )

    return Response(
        {"errors": "Email is required."},
        status=status.HTTP_400_BAD_REQUEST,
    )


@swagger_auto_schema(
    method="post",
    operation_summary="Confirm Password Reset",
    operation_description="Takes a user ID (uid) and a reset key, along with a new password. If valid, updates the user's password.",
    manual_parameters=[
        openapi.Parameter(
            "uid", openapi.IN_PATH, description="User ID", type=openapi.TYPE_STRING
        ),
        openapi.Parameter(
            "key",
            openapi.IN_PATH,
            description="Password reset key",
            type=openapi.TYPE_STRING,
        ),
    ],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "password": openapi.Schema(type=openapi.TYPE_STRING, format="password"),
            "password2": openapi.Schema(type=openapi.TYPE_STRING, format="password"),
        },
        required=["password", "password2"],
    ),
    responses={
        201: openapi.Response(
            description="Password successfully changed",
            examples={"application/json": {"detail": "Password Successfully changed."}},
        ),
        400: openapi.Response(
            description="Passwords do not match",
            examples={"application/json": {"detail": "Passwords do not match."}},
        ),
        404: openapi.Response(
            description="Invalid user or reset key",
            examples={
                "application/json": {
                    "detail": "User DoesNot Exist or Reset Password Key is Invalid"
                }
            },
        ),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def confirm_reset_password(request, uid, key):
    """
    The confirm reset password takes in two arguments
        uid - User id
        key - Key generated from the reset_password
    and the post data
        password
        password2

    Checks if both are valid in the database
        changes the password of the user
    """
    try:
        user = get_object_or_404(User, id=uid)
        if user.auth_provider == "google":
            return Response({"error": "Use Google login"})
        reset_pwd_object = get_object_or_404(PasswordReset_keys, user=user, key=key)

        if reset_pwd_object.exp <= timezone.now():
            return Response(
                {"detail": _("Key has expired.")}, status=status.HTTP_404_NOT_FOUND
            )

        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            return Response(
                {"detail": _("Passwords do not match.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(password)
        user.save()

        return Response(
            {"detail": _("Password Successfully changed.")},
            status=status.HTTP_201_CREATED,
        )

    except User.DoesNotExist or PasswordReset_keys.DoesNotExist:
        return Response(
            {"detail": _("User DoesNot Exist or Reset Password Key is Invalid")},
            status=status.HTTP_404_NOT_FOUND,
        )
