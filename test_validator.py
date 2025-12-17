"""
Test file demonstrating all the new validator features:
- Pattern (regex) validation
- Password validation
- Enum/Choices validation
- Nested validators
- Default values
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List

from validator import BaseValidator, Field, ValidationError, PasswordValidator


# ============================================================================
# ENUM DEFINITIONS
# ============================================================================

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"
    GUEST = "guest"


class OrderStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"


# ============================================================================
# NESTED VALIDATOR EXAMPLES
# ============================================================================

class AddressValidator(BaseValidator):
    """Validates address data"""
    street: str = Field(str, max_length=200)
    city: str = Field(str, max_length=100)
    state: str = Field(str, max_length=50, required=False, default="")
    postal_code: str = Field(
        str,
        pattern=r'^\d{5}(-\d{4})?$',  # US ZIP code format
        pattern_message="Invalid postal code format. Expected: 12345 or 12345-6789"
    )
    country: str = Field(str, max_length=50, default="USA")


class ContactInfoValidator(BaseValidator):
    """Validates contact information"""
    phone: str = Field(
        str,
        pattern=r'^\+?1?\d{10,14}$',
        pattern_message="Invalid phone number format"
    )
    email: str = Field(str, email=True, allow_disposable_email=False)


# ============================================================================
# MAIN VALIDATORS WITH NEW FEATURES
# ============================================================================

class UserRegistrationValidator(BaseValidator):
    """
    Complete user registration validator demonstrating all new features
    """
    # Basic fields
    username: str = Field(
        str,
        pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$',
        pattern_message="Username must start with a letter, contain only letters, numbers, and underscores, and be 3-30 characters"
    )

    # Email field
    email: str = Field(str, email=True, allow_disposable_email=False)

    # Password with strength validation
    password: str = Field(
        str,
        password=True,
        password_strength='strong',  # Requires 12+ chars, upper, lower, digit, special
        password_blacklist={'companyname', 'company123'}
    )

    # Enum validation
    role: str = Field(str, enum=UserRole, default="user")

    # Choices validation
    subscription: str = Field(
        str,
        choices=['free', 'basic', 'premium', 'enterprise'],
        default='free'
    )

    # Nested validator
    address: AddressValidator = Field(AddressValidator, required=False)

    # Nested validator (required)
    contact: ContactInfoValidator = Field(ContactInfoValidator)

    # Default with factory
    created_at: str = Field(
        str,
        default_factory=lambda: datetime.now().isoformat()
    )

    # Optional field with default
    is_active: bool = Field(bool, default=True)
    
    # Age with range validation
    age: int = Field(int, min_value=13, max_value=120, required=False)


class ProductValidator(BaseValidator):
    """Product validator with various field types"""
    name: str = Field(str, no_empty=True, max_length=100)
    sku: str = Field(
        str,
        pattern=r'^[A-Z]{3}-\d{4}$',
        pattern_message="SKU must be in format ABC-1234"
    )
    price: float = Field(float, min_value=0.01)
    quantity: int = Field(int, min_value=0, default=0)
    category: str = Field(
        str,
        choices=['electronics', 'clothing', 'food', 'books', 'other']
    )
    tags: List[str] = Field(List[str], required=False, default_factory=list)


class OrderValidator(BaseValidator):
    """Order validator with enum status"""
    order_id: str = Field(
        str,
        pattern=r'^ORD-\d{8}$',
        pattern_message="Order ID must be in format ORD-12345678"
    )
    status: str = Field(str, enum=OrderStatus, default="pending")
    customer_email: str = Field(str, email=True)
    shipping_address: AddressValidator = Field(AddressValidator)
    total: float = Field(float, min_value=0)


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_pattern_validation():
    """Test regex pattern validation"""
    print("\n" + "="*60)
    print("Testing Pattern (Regex) Validation")
    print("="*60)
    
    # Valid product
    try:
        product = ProductValidator(
            name="Laptop",
            sku="ABC-1234",
            price=999.99,
            category="electronics"
        )
        print(f"[PASS] Valid product: {product.dict()}")
    except ValidationError as e:
        print(f"[FAIL] Unexpected error: {e.errors()}")
    
    # Invalid SKU
    try:
        ProductValidator(
            name="Phone",
            sku="invalid-sku",
            price=499.99,
            category="electronics"
        )
        print("[FAIL] Should have failed with invalid SKU")
    except ValidationError as e:
        print(f"[PASS] Correct pattern error: {e.errors()[0]['msg']}")


def test_password_validation():
    """Test password strength validation"""
    print("\n" + "="*60)
    print("Testing Password Validation")
    print("="*60)
    
    # Test PasswordValidator directly
    passwords = [
        ("weak", "Passw0rd!Strong"),  # Strong password
        ("Common!", "password123"),     # Too common
        ("Short!", "Ab1!"),            # Too short
        ("NoSpecial", "Password123"),   # No special char (for strong)
    ]
    
    for desc, pwd in passwords:
        strength = PasswordValidator.get_strength(pwd)
        print(f"  '{desc}': {pwd[:10]}... -> Strength: {strength}")


def test_enum_validation():
    """Test enum validation"""
    print("\n" + "="*60)
    print("Testing Enum Validation")
    print("="*60)
    
    # Valid enum by value
    try:
        order = OrderValidator(
            order_id="ORD-12345678",
            status="shipped",
            customer_email="test@example.com",
            shipping_address={
                "street": "123 Main St",
                "city": "New York",
                "postal_code": "10001"
            },
            total=150.00
        )
        print(f"[PASS] Valid order status (by value): {order.status}")
    except ValidationError as e:
        print(f"[FAIL] Error: {e.errors()}")
    
    # Invalid enum value
    try:
        OrderValidator(
            order_id="ORD-12345678",
            status="invalid_status",
            customer_email="test@example.com",
            shipping_address={
                "street": "123 Main St",
                "city": "New York",
                "postal_code": "10001"
            },
            total=150.00
        )
        print("[FAIL] Should have failed with invalid enum")
    except ValidationError as e:
        print(f"[PASS] Correct enum error: {e.errors()[0]['msg'][:50]}...")


def test_choices_validation():
    """Test choices validation"""
    print("\n" + "="*60)
    print("Testing Choices Validation")
    print("="*60)
    
    # Valid choice
    try:
        product = ProductValidator(
            name="Book",
            sku="BOK-9999",
            price=29.99,
            category="books"
        )
        print(f"[PASS] Valid category: {product.category}")
    except ValidationError as e:
        print(f"[FAIL] Error: {e.errors()}")
    
    # Invalid choice
    try:
        ProductValidator(
            name="Mystery Item",
            sku="MYS-0000",
            price=9.99,
            category="mystery"
        )
        print("[FAIL] Should have failed with invalid choice")
    except ValidationError as e:
        print(f"[PASS] Correct choices error: {e.errors()[0]['msg']}")


def test_nested_validators():
    """Test nested validator support"""
    print("\n" + "="*60)
    print("Testing Nested Validators")
    print("="*60)
    
    # Valid nested data
    try:
        order = OrderValidator(
            order_id="ORD-99999999",
            status="processing",
            customer_email="customer@example.com",
            shipping_address={
                "street": "456 Oak Avenue",
                "city": "Los Angeles",
                "state": "CA",
                "postal_code": "90001-1234",
                "country": "USA"
            },
            total=299.99
        )
        print(f"[PASS] Nested address validated:")
        print(f"    Street: {order.shipping_address.street}")
        print(f"    City: {order.shipping_address.city}")
        print(f"    Full dict: {order.dict()}")
    except ValidationError as e:
        print(f"[FAIL] Error: {e.errors()}")
    
    # Invalid nested data
    try:
        OrderValidator(
            order_id="ORD-11111111",
            status="pending",
            customer_email="test@example.com",
            shipping_address={
                "street": "123 Main",
                "city": "NYC",
                "postal_code": "invalid-zip"  # Invalid format
            },
            total=50.00
        )
        print("[FAIL] Should have failed with invalid postal code")
    except ValidationError as e:
        error = e.errors()[0]
        print(f"[PASS] Nested field error at '{error['loc']}': {error['msg']}")


def test_default_values():
    """Test default values and default_factory"""
    print("\n" + "="*60)
    print("Testing Default Values")
    print("="*60)
    
    # Test defaults
    try:
        product = ProductValidator(
            name="Simple Product",
            sku="SMP-0001",
            price=19.99,
            category="other"
        )
        print(f"[PASS] Default quantity: {product.quantity}")  # Should be 0
        print(f"[PASS] Default tags: {product.tags}")  # Should be []
    except ValidationError as e:
        print(f"[FAIL] Error: {e.errors()}")
    
    # Test default_factory (created_at)
    try:
        user = UserRegistrationValidator(
            username="johnsmith",
            email="john@example.com",
            password="SecureP@ssw0rd123!",
            contact={
                "phone": "+12025551234",
                "email": "john@example.com"
            }
        )
        print(f"[PASS] Default role: {user.role}")  # Should be UserRole.USER
        print(f"[PASS] Default subscription: {user.subscription}")  # Should be 'free'
        print(f"[PASS] Default is_active: {user.is_active}")  # Should be True
        print(f"[PASS] Auto-generated created_at: {user.created_at}")
    except ValidationError as e:
        print(f"[FAIL] Error: {e.errors()}")


def test_full_user_registration():
    """Test complete user registration with all features"""
    print("\n" + "="*60)
    print("Testing Complete User Registration")
    print("="*60)
    
    try:
        user = UserRegistrationValidator(
            username="janedoe_2024",
            email="jane@company.com",
            password="MyStr0ng!P@ssword",
            role="admin",
            subscription="premium",
            address={
                "street": "789 Pine Street",
                "city": "Chicago",
                "state": "IL",
                "postal_code": "60601"
            },
            contact={
                "phone": "+13125551234",
                "email": "jane@company.com"
            },
            age=28
        )
        
        print("[PASS] User registration successful!")
        print(f"\nUser Data:")
        data = user.dict()
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            else:
                print(f"  {key}: {value}")
                
    except ValidationError as e:
        print(f"[FAIL] Validation errors:")
        for error in e.errors():
            print(f"    {error['loc']}: {error['msg']}")


if __name__ == "__main__":
    print("\n" + "#"*60)
    print("# VALIDATOR FEATURE TESTS")
    print("#"*60)
    
    test_pattern_validation()
    test_password_validation()
    test_enum_validation()
    test_choices_validation()
    test_nested_validators()
    test_default_values()
    test_full_user_registration()
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60 + "\n")
