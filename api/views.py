from rest_framework.decorators import api_view, permission_classes, parser_classes
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
from rest_framework.parsers import MultiPartParser, FormParser
import resend
import uuid
import requests
from .serializers import (
    ProductSerializer,
    ProfileSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    LoginSerializer,
    OrderSerializer,
    KYCSerializer,
)


from .models import (
    Order,
    OrderItem,
    PasswordReset_keys,
    Product,
    Profile,
    User,
    CartItem,
    UserKYC,
)
from farmlink import settings


def generate_reference():
    return str(uuid.uuid4())


@swagger_auto_schema(
    method="post",
    request_body=UserSerializer,
    operation_summary="Register a new user",
    operation_description="Creates a user and initializes their profile.",
    tags=["auth"],
)
@api_view(["POST"])
def register(request):
    serializer = UserSerializer(data=request.data)
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
    tags=["auth"],
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
                {"error": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method="post",
    operation_summary="Logout a user",
    operation_description="Logs out the authenticated user by blacklisting their refresh token.",
    tags=["auth"],
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
    tags=["password-reset"],
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
    tags=["password-reset"],
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


@swagger_auto_schema(
    method="get",
    operation_summary="Get Current User's Profile",
    operation_description="Retrieves the profile information of the currently authenticated user.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    tags=["profile"],
    responses={
        200: openapi.Response(
            description="Profile data retrieved successfully",
            examples={"application/json": {"id": 1, "user": 1, "phone": "1234567890"}},
        ),
        401: openapi.Response(
            description="Unauthorized",
            examples={
                "application/json": {
                    "detail": "Authentication credentials were not provided."
                }
            },
        ),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_profile(request):
    profile = Profile.objects.get(user=request.user)
    serializer = ProfileSerializer(profile)
    return Response(serializer.data)


@swagger_auto_schema(
    method="put",
    operation_summary="Update Current User's Profile",
    operation_description="Updates the profile information of the currently authenticated user.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
        openapi.Parameter(
            name="first_name",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="First name",
        ),
        openapi.Parameter(
            name="last_name",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Last name",
        ),
        openapi.Parameter(
            name="bio",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Bio description",
        ),
        openapi.Parameter(
            name="pic",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_FILE,
            required=False,
            description="Profile image",
        ),
    ],
    tags=["profile"],
    consumes=["multipart/form-data"],
    responses={
        200: openapi.Response(
            description="Profile updated successfully",
            examples={"application/json": {"id": 1, "user": 1, "phone": "9876543210"}},
        ),
        400: openapi.Response(
            description="Bad request",
            examples={"application/json": {"phone": ["This field is required."]}},
        ),
    },
)
@api_view(["PUT"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def update_profile(request):
    profile = Profile.objects.get(user=request.user)
    serializer = ProfileUpdateSerializer(profile, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)


@swagger_auto_schema(
    method="get",
    operation_summary="List All Products",
    operation_description="Retrieves a list of all products available on the platform.",
    tags=["product"],
    responses={
        200: openapi.Response(
            description="List of products",
            examples={"application/json": [{"id": 1, "name": "Maize", "price": 200.0}]},
        )
    },
)
@api_view(["GET"])
def list_products(request):
    products = Product.objects.all()
    serializer = ProductSerializer(products, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method="post",
    operation_summary="Create a New Product",
    operation_description="Creates a new product and associates it with the authenticated user's profile. Only accessible to authenticated users.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer <access_token>",
            type=openapi.TYPE_STRING,
            required=True,
        ),
        openapi.Parameter(
            name="name",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=True,
            description="Product name",
        ),
        openapi.Parameter(
            name="category",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=True,
            description="Product category",
        ),
        openapi.Parameter(
            name="price",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_NUMBER,
            format="float",
            required=True,
            description="Product price",
        ),
        openapi.Parameter(
            name="quantity",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_NUMBER,
            format="float",
            required=True,
            description="Product quantity available for sale",
        ),
        openapi.Parameter(
            name="location",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Location of the seller",
        ),
        openapi.Parameter(
            name="description",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Optional product description",
        ),
        openapi.Parameter(
            name="image",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_FILE,
            required=True,
            description="Product image file",
        ),
    ],
    tags=["product"],
    consumes=["multipart/form-data"],
    responses={
        201: openapi.Response(
            description="Product created successfully",
            examples={"application/json": {"detail": "Product created successfully."}},
        ),
        400: openapi.Response(
            description="Validation error",
            examples={"application/json": {"detail": "Invalid input data."}},
        ),
        401: openapi.Response(
            description="Authentication credentials were not provided",
            examples={
                "application/json": {
                    "detail": "Authentication credentials were not provided."
                }
            },
        ),
    },
)
@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def create_product(request):
    serializer = ProductSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(owner=request.user)
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)


@swagger_auto_schema(
    method="get",
    operation_summary="Retrieve a Product",
    operation_description="Gets the details of a single product using its ID.",
    manual_parameters=[
        openapi.Parameter(
            "id", openapi.IN_PATH, description="Product ID", type=openapi.TYPE_INTEGER
        ),
    ],
    tags=["product"],
    responses={
        200: openapi.Response(description="Product data retrieved successfully"),
        404: openapi.Response(description="Product not found"),
    },
)
@api_view(["GET"])
@permission_classes([AllowAny])
def retrieve_product(request, id):
    try:
        product = Product.objects.get(id=id)
    except Product.DoesNotExist:
        return Response({"error": "Product not found"}, status=404)

    serializer = ProductSerializer(product)
    return Response(serializer.data)


@swagger_auto_schema(
    method="put",
    operation_summary="Update a Product",
    operation_description="Updates an existing product. Only accessible to the product owner.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
        openapi.Parameter(
            "id", openapi.IN_PATH, description="Product ID", type=openapi.TYPE_INTEGER
        ),
        openapi.Parameter(
            name="name",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Product name",
        ),
        openapi.Parameter(
            name="category",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Product category",
        ),
        openapi.Parameter(
            name="price",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_NUMBER,
            format="float",
            required=False,
            description="Product price",
        ),
        openapi.Parameter(
            name="quantity",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_NUMBER,
            format="float",
            required=False,
            description="Product quantity available for sale",
        ),
        openapi.Parameter(
            name="location",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Location of the seller",
        ),
        openapi.Parameter(
            name="description",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_STRING,
            required=False,
            description="Optional product description",
        ),
        openapi.Parameter(
            name="image",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_FILE,
            required=False,
            description="Product image file",
        ),
    ],
    tags=["product"],
    consumes=["multipart/form-data"],
    responses={
        200: openapi.Response(description="Product updated successfully"),
        400: openapi.Response(description="Invalid data"),
        403: openapi.Response(description="Not allowed"),
        404: openapi.Response(description="Product not found"),
    },
)
@api_view(["PUT"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def update_product(request, id):
    try:
        product = Product.objects.get(id=id, owner=request.user)
    except Product.DoesNotExist:
        return Response({"error": "Product not found or unauthorized"}, status=404)

    serializer = ProductSerializer(product, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)


@swagger_auto_schema(
    method="delete",
    operation_summary="Delete a Product",
    operation_description="Deletes an existing product. Only accessible to the product owner.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
        openapi.Parameter(
            "id", openapi.IN_PATH, description="Product ID", type=openapi.TYPE_INTEGER
        ),
    ],
    tags=["product"],
    responses={
        204: openapi.Response(description="Product deleted successfully"),
        403: openapi.Response(description="Not allowed"),
        404: openapi.Response(description="Product not found"),
    },
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_product(request, id):
    try:
        product = Product.objects.get(id=id, owner=request.user)
    except Product.DoesNotExist:
        return Response({"error": "Product not found"}, status=404)

    product.delete()
    return Response(status=204)


# Orders


@swagger_auto_schema(
    method="post",
    operation_summary="Add item to cart",
    operation_description="Adds a product to the authenticated user's cart.",
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
        required=["product_id", "quantity"],
        properties={
            "product_id": openapi.Schema(type=openapi.TYPE_INTEGER),
            "quantity": openapi.Schema(type=openapi.TYPE_INTEGER),
        },
    ),
    responses={201: "Item added to cart successfully."},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_to_cart(request):
    product_id = request.data.get("product_id")
    quantity = request.data.get("quantity", 1)

    if not product_id:
        return Response({"detail": "Product ID is required."}, status=400)

    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return Response({"detail": "Product not found."}, status=404)

    cart_item, created = CartItem.objects.get_or_create(
        user=request.user, product=product
    )

    if not created:
        cart_item.quantity += int(quantity)
    else:
        cart_item.quantity = int(quantity)

    cart_item.save()

    return Response({"detail": "Item added to cart successfully."}, status=201)


@swagger_auto_schema(
    method="get",
    operation_summary="Get cart items",
    operation_description="Returns all items in the authenticated user's cart.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    responses={200: "List of cart items.", 404: "Not found"},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_cart(request):
    items = CartItem.objects.filter(user=request.user).select_related("product")
    response = [
        {
            "product_id": item.product.id,
            "name": item.product.name,
            "price": item.product.price,
            "quantity": item.quantity,
            "subtotal": item.get_total_price(),
        }
        for item in items
    ]
    return Response(response)


@swagger_auto_schema(
    method="get",
    operation_summary="List All Orders",
    operation_description="Admins or logistics partners can view all orders.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    tags=["orders"],
    responses={200: OrderSerializer(many=True)},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_all_orders(request):
    if request.user.is_staff or request.user.orders.exists():
        orders = Order.objects.all()
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    return Response({"detail": "Not authorized."}, status=403)


@swagger_auto_schema(
    method="get",
    operation_summary="List My Orders",
    operation_description="Authenticated buyers can view their own orders.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    tags=["orders"],
    responses={200: OrderSerializer(many=True)},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_my_orders(request):
    orders = Order.objects.filter(buyer=request.user)
    serializer = OrderSerializer(orders, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method="post",
    operation_summary="Create order from cart",
    operation_description="Creates an order and order items from the user's cart, then clears the cart.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {access_token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    responses={201: "Order created successfully."},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_order_from_cart(request):
    cart = get_object_or_404(CartItem, user=request.user)
    cart_items = cart.items.select_related("product")

    if not cart_items.exists():
        return Response({"detail": "Cart is empty."}, status=400)

    total_amount = sum(item.product.price * item.quantity for item in cart_items)
    order = Order.objects.create(
        buyer=request.user,
        delivery_status="pending",
        payment_status="pending",
        order_status="processing",
        total_amount=total_amount,
    )

    for item in cart_items:
        OrderItem.objects.create(
            order=order,
            product=item.product,
            quantity=item.quantity,
            price=item.product.price,
        )

    # Clear cart
    cart.items.all().delete()

    return Response(
        {"detail": "Order created successfully.", "order_id": order.id}, status=201
    )


@swagger_auto_schema(
    method="get",
    operation_summary="Get Single Order",
    operation_description="Retrieve a specific order by ID.",
    tags=["orders"],
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
        openapi.Parameter(
            "id", openapi.IN_PATH, description="Order ID", type=openapi.TYPE_INTEGER
        ),
    ],
    responses={200: OrderSerializer()},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_order(request, id):
    try:
        order = Order.objects.get(id=id)
        if (
            request.user != order.buyer
            and not request.user.is_staff
            and request.user != order.logistics_partner
        ):
            return Response({"detail": "Not authorized."}, status=403)
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    except Order.DoesNotExist:
        return Response({"detail": "Order not found."}, status=404)


@swagger_auto_schema(
    method="put",
    operation_summary="Update Order Status",
    operation_description="Admins or logistics partners can update order status fields.",
    tags=["orders"],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "delivery_status": openapi.Schema(type=openapi.TYPE_STRING),
            "payment_status": openapi.Schema(type=openapi.TYPE_STRING),
            "order_status": openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=[],
    ),
    manual_parameters=[
        openapi.Parameter(
            "id", openapi.IN_PATH, description="Order ID", type=openapi.TYPE_INTEGER
        ),
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    responses={200: OrderSerializer()},
)
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_order_status(request, id):
    try:
        order = Order.objects.get(id=id)
        if not (request.user.is_staff or request.user == order.logistics_partner):
            return Response({"detail": "Not authorized."}, status=403)

        data = request.data
        for field in ["delivery_status", "payment_status", "order_status"]:
            if field in data:
                setattr(order, field, data[field])
        order.save()
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    except Order.DoesNotExist:
        return Response({"detail": "Order not found."}, status=404)


@swagger_auto_schema(
    method="post",
    operation_summary="Submit KYC Documents",
    operation_description="Allows an authenticated user to submit their KYC documents for verification. Uploads typically include ID type and document file.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {access_token}",
            type=openapi.TYPE_STRING,
            required=True,
        )
    ],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=["id_type", "id_number"],
        properties={
            "id_type": openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Type of ID document (e.g., 'national_id', 'passport')",
            ),
            "id_number": openapi.Schema(
                type=openapi.TYPE_NUMBER,
                description="ID Number (e.g., 'NIN', 'Voter's card')",
            ),
        },
    ),
    responses={
        201: openapi.Response(description="KYC submitted successfully."),
        400: openapi.Response(description="Validation error or already submitted."),
        500: openapi.Response(description="Internal server error."),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def submit_kyc(request):
    """
    Submit KYC documents for verification.
    """
    try:
        try:
            # Try to access user's existing KYC (if using OneToOneField)
            existing_kyc = request.user.kyc
            kyc_data = KYCSerializer(existing_kyc).data
            return Response(
                {
                    "detail": "KYC already submitted.",
                    "kyc_details": kyc_data,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except UserKYC.DoesNotExist:
            pass

        serializer = KYCSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(
                {"detail": "KYC submitted successfully."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@swagger_auto_schema(
    method="get",
    operation_summary="Get KYC Status",
    operation_description="Retrieves the KYC submission status of the authenticated user.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {access_token}",
            type=openapi.TYPE_STRING,
            required=True,
        )
    ],
    responses={
        200: openapi.Response(
            description="KYC status retrieved",
            examples={
                "application/json": {
                    "status": "verified",
                    "document_type": "national_id",
                    "submitted_at": "2025-07-10T12:30:00Z",
                }
            },
        ),
        500: openapi.Response(description="Internal server error."),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kyc_status(request):
    """
    Get the current user's KYC submission and verification status.
    """
    try:
        if not hasattr(request.user, "kyc"):
            return Response({"status": "not_submitted"}, status=status.HTTP_200_OK)
        kyc = request.user.kyc
        print(kyc)
        return Response(
            {
                "status": "verified" if kyc.is_verified else "pending",
                "id_type": kyc.id_type,
                "submitted_at": kyc.submitted_at,
            }
        )
    except Exception as e:
        return Response(
            {"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@swagger_auto_schema(
    method="post",
    operation_summary="Initialize Order Payment",
    operation_description="Starts Paystack payment process for a specific order and returns payment URL.",
    manual_parameters=[
        openapi.Parameter(
            "order_id",
            openapi.IN_PATH,
            description="ID of the order to be paid for",
            type=openapi.TYPE_INTEGER,
        ),
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {access_token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    responses={
        200: openapi.Response(description="Payment initialized successfully"),
        400: openapi.Response(description="Validation or business logic error"),
        404: openapi.Response(description="Order not found"),
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def initiate_order_payment(request, order_id):
    """
    Initialize a Paystack payment for a given order.
    """
    try:
        order = Order.objects.get(id=order_id, buyer=request.user)
    except Order.DoesNotExist:
        return Response({"error": "Order not found."}, status=404)

    if order.payment_status == "paid":
        return Response({"message": "Order already paid for."}, status=400)

    reference = generate_reference()

    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    data = {
        "email": request.user.email,
        "amount": int(order.total_amount * 100),
        "reference": reference,
        "callback_url": f"localhost/orders/payment/verify",
    }

    response = requests.post(
        "https://api.paystack.co/transaction/initialize", json=data, headers=headers
    )
    result = response.json()

    if result.get("status") is True:

        order.reference = reference
        order.save()

        return Response(
            {
                "authorization_url": result["data"]["authorization_url"],
                "reference": reference,
            }
        )

    return Response(
        {"error": result.get("message", "Payment initialization failed.")}, status=400
    )


@swagger_auto_schema(
    method="get",
    operation_summary="Verify Order Payment",
    operation_description="Verifies a Paystack transaction and updates the payment status of the order.",
    manual_parameters=[
        openapi.Parameter(
            "reference",
            openapi.IN_PATH,
            description="Paystack transaction reference",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            description="Bearer {access_token}",
            type=openapi.TYPE_STRING,
            required=True,
        ),
    ],
    responses={
        200: openapi.Response(description="Payment verified and order marked as paid"),
        404: openapi.Response(description="Transaction or order not found"),
        400: openapi.Response(description="Payment failed or already verified"),
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def verify_order_payment(request, reference):
    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}

    response = requests.get(
        f"https://api.paystack.co/transaction/verify/{reference}", headers=headers
    )
    result = response.json()

    if result.get("status") and result["data"]["status"] == "success":
        order = Order.objects.filter(reference=reference).first()
        if order:
            order.payment_status = "paid"
            order.save()

        return Response({"message": "Payment verified. Order marked as paid."})

    return Response(
        {"error": "Verification failed or payment not successful."}, status=400
    )


# Admin Processes


@swagger_auto_schema(
    method="get",
    operation_summary="List Users (Admin)",
    operation_description="Returns a list of all registered users. Admin only.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            description="Bearer <token>",
            required=True,
        )
    ],
    tags=["admin"],
    responses={200: UserSerializer(many=True)},
)
@api_view(["GET"])
@permission_classes([IsAdminUser])
def list_users(request):
    users = User.objects.all().order_by("-date_joined")
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method="get",
    operation_summary="Retrieve User (Admin)",
    operation_description="Retrieve details of a single user by ID. Admin only.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            description="Bearer <token>",
            required=True,
        )
    ],
    tags=["admin"],
    responses={200: UserSerializer()},
)
@api_view(["GET"])
@permission_classes([IsAdminUser])
def get_user(request, id):
    try:
        user = User.objects.get(id=id)
        serializer = UserSerializer(user)
        return Response(serializer.data)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=404)


@swagger_auto_schema(
    method="delete",
    operation_summary="Delete User (Admin)",
    operation_description="Permanently delete a user. Admin only.",
    manual_parameters=[
        openapi.Parameter(
            name="Authorization",
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            description="Bearer <token>",
            required=True,
        )
    ],
    tags=["admin"],
    responses={204: "User deleted successfully"},
)
@api_view(["DELETE"])
@permission_classes([IsAdminUser])
def delete_user(request, id):
    try:
        user = User.objects.get(id=id)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=404)
