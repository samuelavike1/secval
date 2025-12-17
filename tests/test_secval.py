"""
Test file for SecVal - Rust-powered Python validation library

Run with: pytest tests/test_secval.py -v
"""
import pytest
from datetime import datetime
from enum import Enum
from typing import Optional, List

from secval import (
    BaseValidator,
    Field,
    ValidationError,
    StringSanitizer,
    EmailValidator,
    PasswordValidator,
)


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
# VALIDATOR DEFINITIONS
# ============================================================================

class AddressValidator(BaseValidator):
    """Validates address data"""
    street: str = Field(str, max_length=200)
    city: str = Field(str, max_length=100)
    state: str = Field(str, max_length=50, required=False, default="")
    postal_code: str = Field(
        str,
        pattern=r'^\d{5}(-\d{4})?$',
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


class UserRegistrationValidator(BaseValidator):
    """Complete user registration validator"""
    username: str = Field(
        str,
        pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$',
        pattern_message="Username must start with a letter and be 3-30 characters"
    )
    email: str = Field(str, email=True, allow_disposable_email=False)
    password: str = Field(
        str,
        password=True,
        password_strength='strong',
        password_blacklist={'companyname', 'company123'}
    )
    role: str = Field(str, enum=UserRole, default="user")
    subscription: str = Field(
        str,
        choices=['free', 'basic', 'premium', 'enterprise'],
        default='free'
    )
    address: AddressValidator = Field(AddressValidator, required=False)
    contact: ContactInfoValidator = Field(ContactInfoValidator)
    created_at: str = Field(str, default_factory=lambda: datetime.now().isoformat())
    is_active: bool = Field(bool, default=True)


class ProductValidator(BaseValidator):
    """Product validator"""
    name: str = Field(str, no_empty=True, max_length=100)
    sku: str = Field(
        str,
        pattern=r'^[A-Z]{3}-\d{4}$',
        pattern_message="SKU must be in format ABC-1234"
    )
    price: float = Field(float, min_value=0.01)
    quantity: int = Field(int, min_value=0, default=0)
    category: str = Field(str, choices=['electronics', 'clothing', 'food', 'books', 'other'])
    tags: List[str] = Field(List[str], required=False, default_factory=list)


# ============================================================================
# STRING SANITIZER TESTS
# ============================================================================

class TestStringSanitizer:
    """Tests for StringSanitizer (Rust implementation)"""

    def test_safe_string_passes(self):
        result = StringSanitizer.sanitize("Hello World", True)
        assert "Hello World" in result

    def test_script_tag_rejected(self):
        with pytest.raises(ValueError, match="Script tags are not allowed"):
            StringSanitizer.sanitize("<script>alert('xss')</script>", True)

    def test_html_tag_rejected(self):
        with pytest.raises(ValueError, match="HTML tags are not allowed"):
            StringSanitizer.sanitize("<div>content</div>", True)

    def test_event_handler_rejected(self):
        with pytest.raises(ValueError, match="JavaScript event handlers are not allowed"):
            StringSanitizer.sanitize("onclick=alert(1)", True)

    def test_sql_injection_rejected(self):
        with pytest.raises(ValueError, match="SQL injection"):
            StringSanitizer.sanitize("'; DROP TABLE users; --", True)

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="Path traversal"):
            StringSanitizer.sanitize("../../../etc/passwd", True)

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="Null bytes"):
            StringSanitizer.sanitize("file.txt\x00.jpg", True)

    def test_non_strict_mode_cleans(self):
        result = StringSanitizer.sanitize("<b>bold</b>", False)
        assert "<b>" not in result

    def test_is_safe_returns_bool(self):
        assert StringSanitizer.is_safe("Hello World") is True
        assert StringSanitizer.is_safe("<script>bad</script>") is False


# ============================================================================
# EMAIL VALIDATOR TESTS
# ============================================================================

class TestEmailValidator:
    """Tests for EmailValidator (Rust implementation)"""

    def test_valid_email(self):
        result = EmailValidator.validate("test@example.com")
        assert result == "test@example.com"

    def test_email_normalized_to_lowercase(self):
        result = EmailValidator.validate("Test@EXAMPLE.COM")
        assert result == "test@example.com"

    def test_email_trimmed(self):
        result = EmailValidator.validate("  test@example.com  ")
        assert result == "test@example.com"

    def test_invalid_format_rejected(self):
        with pytest.raises(ValueError, match="Invalid email"):
            EmailValidator.validate("not-an-email")

    def test_empty_email_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            EmailValidator.validate("")

    def test_disposable_email_blocked(self):
        with pytest.raises(ValueError, match="Disposable"):
            EmailValidator.validate("test@mailinator.com", allow_disposable=False)

    def test_disposable_email_allowed_by_default(self):
        result = EmailValidator.validate("test@mailinator.com", allow_disposable=True)
        assert result == "test@mailinator.com"

    def test_is_valid_returns_bool(self):
        assert EmailValidator.is_valid("test@example.com") is True
        assert EmailValidator.is_valid("invalid") is False


# ============================================================================
# PASSWORD VALIDATOR TESTS
# ============================================================================

class TestPasswordValidator:
    """Tests for PasswordValidator (Rust implementation)"""

    def test_strong_password_passes(self):
        result = PasswordValidator.validate("MyStr0ng!P@ss", "strong")
        assert result == "MyStr0ng!P@ss"

    def test_weak_password_rejected_for_strong(self):
        with pytest.raises(ValueError, match="at least 12 characters"):
            PasswordValidator.validate("weak", "strong")

    def test_no_uppercase_rejected(self):
        with pytest.raises(ValueError, match="uppercase"):
            PasswordValidator.validate("nouppercase1!", "strong")

    def test_no_digit_rejected(self):
        with pytest.raises(ValueError, match="digit"):
            PasswordValidator.validate("NoDigitHere!", "strong")

    def test_no_special_rejected_for_strong(self):
        with pytest.raises(ValueError, match="special"):
            PasswordValidator.validate("NoSpecial123", "strong")

    def test_common_password_rejected(self):
        with pytest.raises(ValueError, match="too common"):
            PasswordValidator.validate("password123", "medium")

    def test_get_strength(self):
        assert PasswordValidator.get_strength("MyStr0ng!P@ss") == "strong"
        assert PasswordValidator.get_strength("Password1") == "medium"
        assert PasswordValidator.get_strength("simple") == "weak"
        assert PasswordValidator.get_strength("abc") == "invalid"

    def test_is_valid_returns_bool(self):
        assert PasswordValidator.is_valid("MyStr0ng!P@ss", "strong") is True
        assert PasswordValidator.is_valid("weak", "strong") is False


# ============================================================================
# PATTERN VALIDATION TESTS
# ============================================================================

class TestPatternValidation:
    """Tests for regex pattern validation"""

    def test_valid_pattern_passes(self):
        product = ProductValidator(
            name="Laptop",
            sku="ABC-1234",
            price=999.99,
            category="electronics"
        )
        assert product.sku == "ABC-1234"

    def test_invalid_pattern_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ProductValidator(
                name="Phone",
                sku="invalid-sku",
                price=499.99,
                category="electronics"
            )
        errors = exc_info.value.errors()
        assert any("sku" in str(e["loc"]) for e in errors)


# ============================================================================
# CHOICES VALIDATION TESTS
# ============================================================================

class TestChoicesValidation:
    """Tests for choices validation"""

    def test_valid_choice_passes(self):
        product = ProductValidator(
            name="Book",
            sku="BOK-9999",
            price=29.99,
            category="books"
        )
        assert product.category == "books"

    def test_invalid_choice_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ProductValidator(
                name="Mystery",
                sku="MYS-0000",
                price=9.99,
                category="mystery"
            )
        errors = exc_info.value.errors()
        assert any("must be one of" in e["msg"] for e in errors)


# ============================================================================
# ENUM VALIDATION TESTS
# ============================================================================

class TestEnumValidation:
    """Tests for enum validation"""

    def test_valid_enum_by_value(self):
        user = UserRegistrationValidator(
            username="johnsmith",
            email="john@example.com",
            password="MyStr0ng!P@ss123",
            role="admin",
            contact={"phone": "+12025551234", "email": "john@example.com"}
        )
        assert user.role == UserRole.ADMIN

    def test_invalid_enum_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationValidator(
                username="johnsmith",
                email="john@example.com",
                password="MyStr0ng!P@ss123",
                role="superuser",
                contact={"phone": "+12025551234", "email": "john@example.com"}
            )
        errors = exc_info.value.errors()
        assert any("Invalid enum" in e["msg"] for e in errors)


# ============================================================================
# NESTED VALIDATOR TESTS
# ============================================================================

class TestNestedValidators:
    """Tests for nested validator support"""

    def test_valid_nested_data(self):
        user = UserRegistrationValidator(
            username="janedoe",
            email="jane@example.com",
            password="MyStr0ng!P@ss123",
            address={
                "street": "123 Main St",
                "city": "New York",
                "postal_code": "10001"
            },
            contact={"phone": "+12025551234", "email": "jane@example.com"}
        )
        assert user.address.city == "New York"
        assert user.address.country == "USA"  # Default

    def test_nested_error_includes_path(self):
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationValidator(
                username="janedoe",
                email="jane@example.com",
                password="MyStr0ng!P@ss123",
                address={
                    "street": "123 Main St",
                    "city": "NYC",
                    "postal_code": "invalid"
                },
                contact={"phone": "+12025551234", "email": "jane@example.com"}
            )
        errors = exc_info.value.errors()
        assert any("address.postal_code" in str(e["loc"]) for e in errors)

    def test_nested_validators_in_dict(self):
        user = UserRegistrationValidator(
            username="janedoe",
            email="jane@example.com",
            password="MyStr0ng!P@ss123",
            address={
                "street": "123 Main St",
                "city": "New York",
                "postal_code": "10001"
            },
            contact={"phone": "+12025551234", "email": "jane@example.com"}
        )
        data = user.dict()
        assert isinstance(data["address"], dict)
        assert data["address"]["city"] == "New York"


# ============================================================================
# DEFAULT VALUES TESTS
# ============================================================================

class TestDefaultValues:
    """Tests for default values and default_factory"""

    def test_static_default(self):
        product = ProductValidator(
            name="Simple Product",
            sku="SMP-0001",
            price=19.99,
            category="other"
        )
        assert product.quantity == 0  # Default value

    def test_default_factory(self):
        product = ProductValidator(
            name="Simple Product",
            sku="SMP-0001",
            price=19.99,
            category="other"
        )
        assert product.tags == []  # Default factory (list)

    def test_default_factory_creates_new_instance(self):
        p1 = ProductValidator(name="P1", sku="AAA-0001", price=10, category="other")
        p2 = ProductValidator(name="P2", sku="BBB-0002", price=20, category="other")
        p1.tags.append("tag1")
        assert p2.tags == []  # Different instance


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Tests for error handling and response format"""

    def test_error_structure(self):
        with pytest.raises(ValidationError) as exc_info:
            ProductValidator(
                name="",
                sku="invalid",
                price=-10,
                category="unknown"
            )
        errors = exc_info.value.errors()
        
        # Each error should have loc, type, and msg
        for error in errors:
            assert "loc" in error
            assert "type" in error
            assert "msg" in error
            assert isinstance(error["loc"], tuple)

    def test_missing_field_error_type(self):
        with pytest.raises(ValidationError) as exc_info:
            ProductValidator(
                sku="ABC-1234",
                price=10,
                category="other"
            )  # Missing 'name'
        errors = exc_info.value.errors()
        name_errors = [e for e in errors if "name" in str(e["loc"])]
        assert len(name_errors) > 0
        assert name_errors[0]["type"] == "missing"

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            ProductValidator(
                name="Test",
                sku="ABC-1234",
                price=10,
                category="other",
                unknown_field="value"
            )
        errors = exc_info.value.errors()
        assert any(e["type"] == "extra_forbidden" for e in errors)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple features"""

    def test_complete_user_registration(self):
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
            }
        )

        data = user.dict()
        
        assert data["username"] == "janedoe_2024"
        assert data["email"] == "jane@company.com"
        assert data["role"] == "admin"  # Enum value
        assert data["subscription"] == "premium"
        assert data["is_active"] is True  # Default
        assert "created_at" in data  # Default factory
        assert data["address"]["city"] == "Chicago"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
