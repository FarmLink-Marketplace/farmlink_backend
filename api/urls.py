from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("auth/register/", views.register, name="register"),
    path("auth/login/", views.login, name="login"),
    path("auth/logout/", views.logout, name="logout"),
    path("auth/refresh-token/", TokenRefreshView.as_view(), name="refresh-token"),
    path("profile/", views.get_profile, name="user-profile"),
    path("profile/update/", views.update_profile, name="update user-profile"),
    path("products/", views.list_products, name="get products"),
    path("products/post/", views.create_product, name="post products"),
    path("products/<int:id>/", views.retrieve_product, name="get product details"),
    path(
        "products/update/<int:id>/", views.update_product, name="update product details"
    ),
    path("products/delete/<int:id>/", views.delete_product, name="delete product"),
    path("cart/items/", views.add_to_cart, name="add_to_cart"),
    path("cart/", views.get_cart, name="get_cart"),
    path("orders/create/", views.create_order_from_cart, name="create-order"),
    path("orders/", views.list_all_orders, name="list-all-orders"),
    path("orders/my/", views.list_my_orders, name="list-my-orders"),
    path("orders/<int:id>/", views.get_order, name="get-order"),
    path(
        "orders/update/<int:id>/", views.update_order_status, name="update-order-status"
    ),
    path("auth/kyc/", views.submit_kyc, name="submit_kyc"),
    path("auth/kyc/status/", views.get_kyc_status, name="get_kyc_status"),
    path("orders/<order_id>/pay/", views.initiate_order_payment, name="make-payment"),
    path(
        "orders/payment/verify/<reference>/",
        views.verify_order_payment,
        name="verify-payment",
    ),
]
