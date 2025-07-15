from django.contrib.auth.models import AbstractUser
from django.db import models
from .managers import CustomUserManager
from cloudinary.models import CloudinaryField


class User(AbstractUser):
    USER_TYPES = (
        ("farmer", "Farmer"),
        ("consumer", "Consumer"),
        ("logistics", "Logistics Partner"),
        ("admin", "Admin"),
    )

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True, db_index=True)
    phone_number = models.CharField(max_length=20, unique=True)
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    username = None
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.user_type})"


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    pic = CloudinaryField("pic", blank=True, null=True, folder="profiles")
    bio = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Profile of {self.user.email}"


class UserKYC(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="kyc")
    id_type = models.CharField(max_length=50)
    id_number = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"KYC - {self.user.email}"


class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.IntegerField(default=0)

    def __str__(self):
        return f"Wallet of {self.user.email}"


class WalletTransaction(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE)
    amount = models.IntegerField()
    transaction_type = models.CharField(max_length=20)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transaction {self.id} - {self.wallet.user.email}"


class Product(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    description = models.CharField(max_length=3000)
    price = models.PositiveIntegerField()
    quantity = models.PositiveIntegerField()
    location = models.CharField(max_length=100)
    image = CloudinaryField("image", folder="products")
    is_approved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} - {self.user.email}"


class Order(models.Model):
    buyer = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="orders"
    )
    logistics_partner = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="logistics_orders",
    )
    delivery_status = models.CharField(max_length=50)
    payment_status = models.CharField(max_length=50)
    order_status = models.CharField(max_length=50)
    total_amount = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    reference = models.CharField(max_length=100, unique=True, null=True, blank=True)

    def __str__(self):
        return f"Order {self.id} by {self.buyer.email if self.buyer else 'N/A'}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    unit_price = models.PositiveIntegerField()
    subtotal = models.PositiveIntegerField()
    seller = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sold_items"
    )

    def __str__(self):
        return f"Item {self.product.name} x {self.quantity}"


class Tracking(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    logistics_user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=50)
    location = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Tracking {self.order.id} - {self.status}"


class Review(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.PositiveSmallIntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review {self.id} by {self.reviewer.email}"


class Payment(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    method = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    amount = models.PositiveIntegerField()
    reference = models.CharField(max_length=100, unique=True)
    paid_at = models.DateTimeField()

    def __str__(self):
        return f"Payment {self.reference} - {self.status}"


class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    plan_type = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    start_date = models.DateField()

    def __str__(self):
        return f"Subscription {self.plan_type} - {self.user.email}"


class SubscriptionItem(models.Model):
    subscription = models.ForeignKey(
        Subscription, on_delete=models.CASCADE, related_name="items"
    )
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.quantity} x {self.product.name} in subscription {self.subscription.id}"


class PasswordReset_keys(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="pwd_keys")
    key = models.CharField(max_length=100)
    exp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class CartItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="cart_items")
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="cart_items"
    )
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "product")
        ordering = ["-added_at"]

    def __str__(self):
        return f"{self.quantity} x {self.product.name} for {self.user.email}"

    def get_total_price(self):
        return self.product.price * self.quantity
