from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Profile, User, Product, Order, UserKYC, CartItem


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "user_type",
            "password",
            "confirm_password",
        ]

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        user = User.objects.create_user(**validated_data)
        Profile.objects.create(user=user)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    pic = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = "__all__"
        read_only_fields = ["user"]

    def get_pic(self, obj):
        request = self.context.get("request")
        if obj.pic and hasattr(obj.pic, "url"):
            if request is not None:
                return request.build_absolute_uri(obj.pic.url)
            return obj.pic.url
        return None


class ProfileUpdateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", required=False)
    last_name = serializers.CharField(source="user.last_name", required=False)
    phone_number = serializers.CharField(source="user.phone_number", required=False)
    pic = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ["bio", "pic", "first_name", "last_name", "phone_number"]

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", {})
        for attr, value in user_data.items():
            setattr(instance.user, attr, value)
        instance.user.save()

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        return instance

    def get_pic(self, obj):
        request = self.context.get("request")
        if obj.pic and hasattr(obj.pic, "url"):
            if request is not None:
                return request.build_absolute_uri(obj.pic.url)
            return obj.pic.url
        return None


class ProductSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    image = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = "__all__"
        read_only_fields = ["owner", "is_approved"]

    def get_image(self, obj):
        request = self.context.get("request")
        if obj.image and hasattr(obj.image, "url"):
            if request is not None:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


class OrderSerializer(serializers.ModelSerializer):
    buyer = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), required=False
    )
    logistics_partner = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )

    class Meta:
        model = Order
        fields = "__all__"
        read_only_fields = ["buyer", "created_at"]


class KYCSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserKYC
        fields = "__all__"
        read_only_fields = ["user", "is_verified", "submitted_at"]


class CartItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity"]
