"""
SecVal Test Suite
==================
A comprehensive test file for the secval package.

Usage:
    1. Install secval: pip install secval
    2. Run this file: python test_secval_features.py
"""

from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

# Try to import secval
try:
    from secval import (
        BaseValidator,
        EmailValidator,
        Field,
        PasswordValidator,
        StringSanitizer,
        ValidationError,
    )

    print("[OK] secval imported successfully!")
except ImportError as e:
    print(f"[FAIL] Could not import secval: {e}")
    print("Install with: pip install secval")
    exit(1)


# ============================================================================
# ENUM DEFINITIONS
# ============================================================================


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class OrderStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"


# ============================================================================
# VALIDATOR DEFINITIONS (using new API - type from annotation)
# ============================================================================


class AddressValidator(BaseValidator):
    street: str = Field(max_length=200)
    city: str = Field(max_length=100)
    postal_code: str = Field(
        pattern=r"^\d{5}(-\d{4})?$",
        pattern_message="Invalid postal code (use 12345 or 12345-6789)",
    )
    country: str = Field(default="USA")


class SimpleValidator(BaseValidator):
    name: str = Field(no_empty=True, max_length=50)
    age: int = Field(min_value=0, max_value=150)
    score: float = Field(min_value=0.0, max_value=100.0)
    active: bool


class ProductValidator(BaseValidator):
    name: str = Field(no_empty=True)
    sku: str = Field(
        pattern=r"^[A-Z]{3}-\d{4}$",
        pattern_message="SKU must be ABC-1234 format",
    )
    price: float = Field(min_value=0.01)
    quantity: int = Field(default=0, min_value=0)
    category: str = Field(choices=["electronics", "clothing", "food", "books"])
    tags: List[str] = Field(default_factory=list)


class UserValidator(BaseValidator):
    username: str = Field(
        pattern=r"^[a-zA-Z][a-zA-Z0-9_]{2,29}$",
        pattern_message="Username must start with letter, 3-30 chars",
    )
    email: str = Field(email=True, allow_disposable_email=False)
    password: str = Field(password=True, password_strength="strong")
    role: str = Field(enum=UserRole, default="user")
    # Use Union with dict to allow passing dict literals without type errors
    address: Optional[AddressValidator | dict[str, Any]] = Field(default=None)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

passed = 0
failed = 0


def test(name: str, condition: bool) -> None:
    """Simple test helper"""
    global passed, failed
    try:
        if condition:
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}")
            failed += 1
    except Exception as e:
        print(f"  [ERROR] {name}: {e}")
        failed += 1


def test_string_sanitizer() -> None:
    """Test StringSanitizer"""
    print("\n--- StringSanitizer Tests ---")

    # Safe string passes
    result = StringSanitizer.sanitize("Hello World", True)
    test("Safe string passes", "Hello" in result)

    # Script tags blocked
    try:
        StringSanitizer.sanitize("<script>alert('xss')</script>", True)
        test("Script tags blocked", False)
    except ValueError:
        test("Script tags blocked", True)

    # HTML tags blocked
    try:
        StringSanitizer.sanitize("<div>text</div>", True)
        test("HTML tags blocked", False)
    except ValueError:
        test("HTML tags blocked", True)

    # SQL injection blocked
    try:
        StringSanitizer.sanitize("'; DROP TABLE users; --", True)
        test("SQL injection blocked", False)
    except ValueError:
        test("SQL injection blocked", True)

    # Path traversal blocked
    try:
        StringSanitizer.sanitize("../../../etc/passwd", True)
        test("Path traversal blocked", False)
    except ValueError:
        test("Path traversal blocked", True)

    # is_safe returns correct values
    test(
        "is_safe() returns True for safe",
        StringSanitizer.is_safe("Hello World") == True,
    )
    test(
        "is_safe() returns False for malicious",
        StringSanitizer.is_safe("<script>bad</script>") == False,
    )


def test_email_validator() -> None:
    """Test EmailValidator"""
    print("\n--- EmailValidator Tests ---")

    # Valid email
    result = EmailValidator.validate("test@example.com")
    test("Valid email passes", result == "test@example.com")

    # Email normalized to lowercase
    result = EmailValidator.validate("TEST@EXAMPLE.COM")
    test("Email normalized to lowercase", result == "test@example.com")

    # Email trimmed
    result = EmailValidator.validate("  test@example.com  ")
    test("Email trimmed", result == "test@example.com")

    # Invalid email rejected
    try:
        EmailValidator.validate("not-an-email")
        test("Invalid email rejected", False)
    except ValueError:
        test("Invalid email rejected", True)

    # Disposable blocked when disabled
    try:
        EmailValidator.validate("test@mailinator.com", False)
        test("Disposable email blocked", False)
    except ValueError:
        test("Disposable email blocked", True)

    # is_valid works
    test(
        "is_valid() for valid email",
        EmailValidator.is_valid("test@example.com") == True,
    )
    test("is_valid() for invalid email", EmailValidator.is_valid("invalid") == False)


def test_password_validator() -> None:
    """Test PasswordValidator"""
    print("\n--- PasswordValidator Tests ---")

    # Strong password passes
    result = PasswordValidator.validate("MyStr0ng!Pass123", "strong")
    test("Strong password passes", result == "MyStr0ng!Pass123")

    # Weak password rejected for strong
    try:
        PasswordValidator.validate("weak", "strong")
        test("Weak password rejected", False)
    except ValueError:
        test("Weak password rejected", True)

    # No uppercase rejected
    try:
        PasswordValidator.validate("nouppercase123!", "strong")
        test("No uppercase rejected", False)
    except ValueError:
        test("No uppercase rejected", True)

    # Common password rejected
    try:
        PasswordValidator.validate("password123", "medium")
        test("Common password rejected", False)
    except ValueError:
        test("Common password rejected", True)

    # get_strength works
    test(
        "get_strength strong",
        PasswordValidator.get_strength("MyStr0ng!Pass123") == "strong",
    )
    # For medium: needs 8+ chars, uppercase, lowercase, digit, but NO special char needed
    medium_pass = "Xk9mNq2pL"  # 9 chars, has upper, lower, digit, definitely not common
    actual = PasswordValidator.get_strength(medium_pass)
    test("get_strength medium", actual == "medium")
    if actual != "medium":
        print(f"    DEBUG: '{medium_pass}' returned '{actual}' (expected 'medium')")
    test("get_strength weak", PasswordValidator.get_strength("simple") == "weak")
    test("get_strength invalid", PasswordValidator.get_strength("ab") == "invalid")


def test_basic_validator() -> None:
    """Test basic type validation"""
    print("\n--- Basic Validator Tests ---")

    # Valid data passes
    v = SimpleValidator(name="John", age=30, score=85.5, active=True)
    test("Valid data passes", v.name == "John" and v.age == 30)

    # dict() returns data
    d = v.dict()
    test("dict() returns data", d["name"] == "John" and d["age"] == 30)

    # Empty string rejected
    try:
        SimpleValidator(name="", age=30, score=85.5, active=True)
        test("Empty string rejected", False)
    except ValidationError:
        test("Empty string rejected", True)

    # Value below min rejected
    try:
        SimpleValidator(name="John", age=-5, score=85.5, active=True)
        test("Value below min rejected", False)
    except ValidationError:
        test("Value below min rejected", True)

    # Value above max rejected
    try:
        SimpleValidator(name="John", age=30, score=150.0, active=True)
        test("Value above max rejected", False)
    except ValidationError:
        test("Value above max rejected", True)


def test_pattern_validation() -> None:
    """Test regex pattern validation"""
    print("\n--- Pattern Validation Tests ---")

    # Valid pattern passes
    p = ProductValidator(
        name="Laptop", sku="ABC-1234", price=999.99, category="electronics"
    )
    test("Valid pattern passes", p.sku == "ABC-1234")

    # Invalid pattern rejected
    try:
        ProductValidator(
            name="Phone", sku="invalid", price=499.99, category="electronics"
        )
        test("Invalid pattern rejected", False)
    except ValidationError as e:
        errors = e.errors()
        has_sku_error = any("sku" in str(err["loc"]) for err in errors)
        test("Invalid pattern rejected", has_sku_error)


def test_choices_validation() -> None:
    """Test choices validation"""
    print("\n--- Choices Validation Tests ---")

    # Valid choice passes
    p = ProductValidator(name="Book", sku="BOK-1234", price=19.99, category="books")
    test("Valid choice passes", p.category == "books")

    # Invalid choice rejected
    try:
        ProductValidator(name="Mystery", sku="MYS-1234", price=9.99, category="mystery")
        test("Invalid choice rejected", False)
    except ValidationError as e:
        errors = e.errors()
        has_choice_error = any("must be one of" in err["msg"] for err in errors)
        test("Invalid choice rejected", has_choice_error)


def test_enum_validation() -> None:
    """Test enum validation"""
    print("\n--- Enum Validation Tests ---")

    # Valid enum passes
    u = UserValidator(
        username="johnsmith", email="john@example.com", password="MyStr0ng!Pass123"
    )
    test("Default enum works", u.role == UserRole.USER)

    # Enum by value
    u2 = UserValidator(
        username="johnsmith",
        email="john@example.com",
        password="MyStr0ng!Pass123",
        role="admin",
    )
    test("Enum by value works", u2.role == UserRole.ADMIN)

    # Invalid enum rejected
    try:
        UserValidator(
            username="johnsmith",
            email="john@example.com",
            password="MyStr0ng!Pass123",
            role="superuser",
        )
        test("Invalid enum rejected", False)
    except ValidationError:
        test("Invalid enum rejected", True)


def test_nested_validators() -> None:
    """Test nested validator support"""
    print("\n--- Nested Validator Tests ---")

    # Valid nested data
    u = UserValidator(
        username="janedoe",
        email="jane@example.com",
        password="MyStr0ng!Pass123",
        address={"street": "123 Main St", "city": "New York", "postal_code": "10001"},
    )
    # address could be AddressValidator or dict at this point
    addr = u.address
    test(
        "Valid nested data passes",
        addr is not None
        and isinstance(addr, AddressValidator)
        and addr.city == "New York",
    )
    test(
        "Nested default works",
        addr is not None
        and isinstance(addr, AddressValidator)
        and addr.country == "USA",
    )

    # Invalid nested data (invalid postal code)
    try:
        UserValidator(
            username="janedoe",
            email="jane@example.com",
            password="MyStr0ng!Pass123",
            address={"street": "123 Main St", "city": "NYC", "postal_code": "invalid"},
        )
        test("Invalid nested rejected", False)
    except ValidationError as e:
        errors = e.errors()
        has_nested_error = any("address" in str(err["loc"]) for err in errors)
        test("Invalid nested rejected", has_nested_error)

    # Nested in dict()
    u2 = UserValidator(
        username="janedoe",
        email="jane@example.com",
        password="MyStr0ng!Pass123",
        address={"street": "123 Main St", "city": "New York", "postal_code": "10001"},
    )
    d = u2.dict()
    test(
        "Nested in dict()",
        isinstance(d["address"], dict) and d["address"]["city"] == "New York",
    )


def test_default_values() -> None:
    """Test default values"""
    print("\n--- Default Values Tests ---")

    # Static default
    p = ProductValidator(name="Item", sku="ITM-0001", price=10.0, category="books")
    test("Static default (quantity)", p.quantity == 0)

    # default_factory
    test("default_factory (tags)", p.tags == [])

    # default_factory creates new instances
    p1 = ProductValidator(name="P1", sku="AAA-0001", price=10.0, category="books")
    p2 = ProductValidator(name="P2", sku="BBB-0001", price=20.0, category="books")
    p1.tags.append("tag1")
    test("default_factory new instances", "tag1" not in p2.tags)

    # created_at auto-generated
    u = UserValidator(
        username="testuser", email="test@example.com", password="MyStr0ng!Pass123"
    )
    test("created_at generated", u.created_at is not None and "T" in u.created_at)


def test_error_handling() -> None:
    """Test error handling"""
    print("\n--- Error Handling Tests ---")

    # Error structure
    try:
        SimpleValidator(name="", age=-5, score=200.0, active=True)
    except ValidationError as e:
        errors = e.errors()
        has_structure = all(
            "loc" in err and "type" in err and "msg" in err for err in errors
        )
        test("Error has loc, type, msg", has_structure)

    # Missing field type
    try:
        SimpleValidator(age=30, score=50.0, active=True)  # type: ignore[call-arg]
    except ValidationError as e:
        errors = e.errors()
        name_errors = [err for err in errors if "name" in str(err["loc"])]
        test(
            "Missing field type is 'missing'",
            len(name_errors) > 0 and name_errors[0]["type"] == "missing",
        )

    # Extra fields rejected
    try:
        SimpleValidator(name="John", age=30, score=50.0, active=True, extra="field")  # type: ignore[call-arg]
    except ValidationError as e:
        errors = e.errors()
        has_extra = any(err["type"] == "extra_forbidden" for err in errors)
        test("Extra fields rejected", has_extra)


def test_list_validation() -> None:
    """Test List type validation"""
    print("\n--- List Validation Tests ---")

    class ListValidator(BaseValidator):
        items: List[str]

    # Valid list
    v = ListValidator(items=["a", "b", "c"])
    test("Valid list passes", v.items == ["a", "b", "c"])

    # Non-list rejected
    try:
        ListValidator(items="not-a-list")  # type: ignore[arg-type]
        test("Non-list rejected", False)
    except ValidationError:
        test("Non-list rejected", True)


def test_optional_fields() -> None:
    """Test Optional field handling"""
    print("\n--- Optional Fields Tests ---")

    class OptionalValidator(BaseValidator):
        required_field: str
        optional_field: Optional[str] = Field(default=None)
        optional_with_default: str = Field(default="default_value")

    # Optional can be omitted
    v = OptionalValidator(required_field="value")
    test("Optional field can be omitted", True)

    # Optional with default
    test("Optional with default", v.optional_with_default == "default_value")

    # Required cannot be omitted
    try:
        OptionalValidator()  # type: ignore[call-arg]
        test("Required field cannot be omitted", False)
    except ValidationError:
        test("Required field cannot be omitted", True)


# ============================================================================
# MAIN
# ============================================================================


def main() -> None:
    print("=" * 60)
    print("SecVal Feature Tests")
    print("=" * 60)

    try:
        import secval

        print(f"Version: {getattr(secval, '__version__', 'unknown')}")
    except Exception:
        pass

    test_string_sanitizer()
    test_email_validator()
    test_password_validator()
    test_basic_validator()
    test_pattern_validation()
    test_choices_validation()
    test_enum_validation()
    test_nested_validators()
    test_default_values()
    test_error_handling()
    test_list_validation()
    test_optional_fields()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        exit(1)


if __name__ == "__main__":
    main()
