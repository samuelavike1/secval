# Secure Validator

A lightweight, security-focused Python validation library for building robust applications. Built with type safety, injection prevention, and developer experience in mind.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Error Handling](#error-handling)
- [Validation Features](#validation-features)
  - [Type Validation](#type-validation)
  - [Required and Optional Fields](#required-and-optional-fields)
  - [String Constraints](#string-constraints)
  - [Numeric Range Validation](#numeric-range-validation)
  - [Email Validation](#email-validation)
  - [Pattern (Regex) Validation](#pattern-regex-validation)
  - [Password Validation](#password-validation)
  - [Choices Validation](#choices-validation)
  - [Enum Validation](#enum-validation)
  - [Nested Validators](#nested-validators)
  - [Default Values](#default-values)
  - [List and Dict Validation](#list-and-dict-validation)
- [Security Features](#security-features)
  - [String Sanitization](#string-sanitization)
  - [XSS Prevention](#xss-prevention)
  - [SQL Injection Protection](#sql-injection-protection)
  - [Path Traversal Protection](#path-traversal-protection)
- [API Reference](#api-reference)
  - [BaseValidator](#basevalidator)
  - [Field Options](#field-options)
  - [ValidationError](#validationerror)
  - [StringSanitizer](#stringsanitizer)
  - [EmailValidator](#emailvalidator)
  - [PasswordValidator](#passwordvalidator)
- [Complete Examples](#complete-examples)

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd secure-validator

# No external dependencies required - pure Python!
```

---

## Quick Start

```python
from validator import BaseValidator, Field, ValidationError

# Define a validator
class UserValidator(BaseValidator):
    name: str = Field(str, no_empty=True, max_length=100)
    email: str = Field(str, email=True)
    age: int = Field(int, min_value=0, max_value=120)

# Validate data
try:
    user = UserValidator(
        name="John Doe",
        email="john@example.com",
        age=30
    )
    
    # Access validated data
    print(user.name)      # "John Doe"
    print(user.email)     # "john@example.com"
    print(user.dict())    # {'name': 'John Doe', 'email': 'john@example.com', 'age': 30}
    
except ValidationError as e:
    print("Validation failed!")
    for error in e.errors():
        print(f"  Field: {error['loc']}, Error: {error['msg']}")
```

---

## Error Handling

### ValidationError Structure

When validation fails, a `ValidationError` exception is raised containing a list of all errors:

```python
from validator import BaseValidator, Field, ValidationError

class ProductValidator(BaseValidator):
    name: str = Field(str, no_empty=True)
    price: float = Field(float, min_value=0.01)
    quantity: int = Field(int, min_value=0)

try:
    product = ProductValidator(
        name="",           # Empty string - error
        price=-10,         # Negative - error
        # quantity missing - error
    )
except ValidationError as e:
    # Get all errors as a list
    errors = e.errors()
    
    for error in errors:
        print(f"Location: {error['loc']}")
        print(f"Type: {error['type']}")
        print(f"Message: {error['msg']}")
        print("---")
```

### Error Response Format

Each error is a dictionary with the following structure:

```python
{
    "loc": ("body", "field_name"),    # Location tuple: (source, field_name)
    "type": "error_type",              # Type of error
    "msg": "Human readable message"    # Detailed error message
}
```

### Error Types

| Error Type | Description | Example |
|------------|-------------|---------|
| `missing` | Required field not provided | `"Field required"` |
| `type_error` | Wrong data type | `"Expected string, got int"` |
| `value_error` | Value constraint violated | `"Value must be at least 0"` |
| `extra_forbidden` | Unknown field provided | `"Extra inputs are not permitted"` |

### Complete Error Handling Example

```python
from validator import BaseValidator, Field, ValidationError

class RegistrationValidator(BaseValidator):
    username: str = Field(str, pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$')
    email: str = Field(str, email=True)
    password: str = Field(str, password=True, password_strength='strong')
    age: int = Field(int, min_value=13)

def register_user(data: dict):
    """Register a new user with validation"""
    try:
        validated = RegistrationValidator(**data)
        
        # Validation passed - use validated data
        return {
            "success": True,
            "user": validated.dict()
        }
        
    except ValidationError as e:
        # Validation failed - return errors
        return {
            "success": False,
            "errors": [
                {
                    "field": error["loc"][1],  # Get field name from location
                    "message": error["msg"]
                }
                for error in e.errors()
            ]
        }

# Test with invalid data
result = register_user({
    "username": "123invalid",  # Starts with number
    "email": "not-an-email",
    "password": "weak",
    "age": 10  # Too young
})

print(result)
# {
#     "success": False,
#     "errors": [
#         {"field": "username", "message": "Value does not match required pattern"},
#         {"field": "email", "message": "Invalid email address format"},
#         {"field": "password", "message": "Password must be at least 12 characters long"},
#         {"field": "age", "message": "Value must be at least 13"}
#     ]
# }
```

### Nested Validator Error Paths

For nested validators, error locations include the full path:

```python
class AddressValidator(BaseValidator):
    postal_code: str = Field(str, pattern=r'^\d{5}$')

class UserValidator(BaseValidator):
    address: AddressValidator = Field(AddressValidator)

try:
    user = UserValidator(address={"postal_code": "invalid"})
except ValidationError as e:
    error = e.errors()[0]
    print(error["loc"])  # ('body', 'address.postal_code')
    print(error["msg"])  # "Value does not match required pattern"
```

---

## Validation Features

### Type Validation

The validator supports these basic types:

```python
class DataValidator(BaseValidator):
    text: str                    # String
    count: int                   # Integer
    price: float                 # Float (accepts int too)
    active: bool                 # Boolean
    items: List[str]             # List of strings
    metadata: Dict[str, Any]     # Dictionary
    maybe_text: Optional[str]    # Optional (can be None)
```

**Type coercion rules:**
- `float` accepts both `int` and `float` values
- `bool` must be exactly `True` or `False` (not `1` or `0`)
- `int` rejects `bool` values (to prevent `True` being treated as `1`)

```python
# Examples
validator = DataValidator(
    text="hello",
    count=42,
    price=19,          # Integer accepted for float field
    active=True,
    items=["a", "b"],
    metadata={"key": "value"},
    maybe_text=None    # None allowed for Optional
)
```

### Required and Optional Fields

```python
class UserValidator(BaseValidator):
    # Required field (default)
    name: str = Field(str, required=True)
    
    # Optional field - can be omitted
    nickname: str = Field(str, required=False)
    
    # Optional with default value
    role: str = Field(str, required=False, default="user")

# Valid - nickname omitted
user = UserValidator(name="John")
print(user.dict())  # {"name": "John", "role": "user"}
```

### Extra Fields Rejection

By default, extra fields not defined in the validator are rejected:

```python
class StrictValidator(BaseValidator):
    name: str

try:
    StrictValidator(name="John", unknown_field="value")
except ValidationError as e:
    print(e.errors()[0])
    # {"loc": ("body", "unknown_field"), "type": "extra_forbidden", "msg": "Extra inputs are not permitted"}
```

### String Constraints

```python
class ProfileValidator(BaseValidator):
    # Maximum length
    username: str = Field(str, max_length=30)
    
    # No empty strings allowed (after stripping whitespace)
    bio: str = Field(str, no_empty=True)
    
    # Both constraints
    title: str = Field(str, max_length=100, no_empty=True)
```

### Numeric Range Validation

```python
class ProductValidator(BaseValidator):
    # Minimum value only
    quantity: int = Field(int, min_value=0)
    
    # Maximum value only
    discount: float = Field(float, max_value=100.0)
    
    # Both minimum and maximum
    rating: float = Field(float, min_value=0.0, max_value=5.0)
    
    # Age range
    age: int = Field(int, min_value=0, max_value=120)
```

### Email Validation

RFC 5322 compliant email validation:

```python
class ContactValidator(BaseValidator):
    # Basic email validation
    email: str = Field(str, email=True)
    
    # Block disposable email domains
    work_email: str = Field(str, email=True, allow_disposable_email=False)
    
    # Custom max length
    notification_email: str = Field(str, email=True, max_length=100)
```

**Email validation checks:**
- Valid format (local@domain.tld)
- Local part: 1-64 characters, no consecutive dots
- Domain: Valid labels, proper TLD
- Optional: Blocks disposable email providers

**Direct EmailValidator usage:**

```python
from validator import EmailValidator

# Validate and normalize
email = EmailValidator.validate("  John@Example.COM  ")
print(email)  # "john@example.com"

# Check if valid
is_valid = EmailValidator.is_valid("test@example.com")  # True
is_valid = EmailValidator.is_valid("invalid-email")      # False

# Block disposable emails
EmailValidator.validate("test@mailinator.com", allow_disposable=False)
# Raises: ValueError("Disposable email addresses are not allowed")
```

### Pattern (Regex) Validation

Apply custom regex patterns to string fields:

```python
class FormValidator(BaseValidator):
    # US phone number
    phone: str = Field(
        str,
        pattern=r'^\+?1?\d{10}$',
        pattern_message="Invalid phone number. Use 10 digits, optionally with +1"
    )
    
    # Username format
    username: str = Field(
        str,
        pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$',
        pattern_message="Username must start with a letter and be 3-30 characters"
    )
    
    # US ZIP code
    postal_code: str = Field(
        str,
        pattern=r'^\d{5}(-\d{4})?$',
        pattern_message="Invalid ZIP code. Use 12345 or 12345-6789 format"
    )
    
    # Hex color
    color: str = Field(
        str,
        pattern=r'^#[0-9A-Fa-f]{6}$',
        pattern_message="Invalid hex color. Use #RRGGBB format"
    )
```

**Pattern options:**
- `pattern`: String or compiled `re.Pattern` object
- `pattern_message`: Custom error message (default: "Value does not match required pattern")

### Password Validation

Three strength levels with comprehensive checks:

```python
class RegistrationValidator(BaseValidator):
    # Weak: minimum 6 characters, no other requirements
    simple_password: str = Field(str, password=True, password_strength='weak')
    
    # Medium (default): 8+ chars, upper, lower, digit, common password check
    standard_password: str = Field(str, password=True, password_strength='medium')
    
    # Strong: 12+ chars, upper, lower, digit, special char, common password check
    secure_password: str = Field(str, password=True, password_strength='strong')
    
    # With custom blacklist
    company_password: str = Field(
        str,
        password=True,
        password_strength='medium',
        password_blacklist={'companyname', 'company2024'}
    )
```

**Strength requirements:**

| Level | Min Length | Uppercase | Lowercase | Digit | Special | Common Check |
|-------|------------|-----------|-----------|-------|---------|--------------|
| `weak` | 6 | No | No | No | No | No |
| `medium` | 8 | Yes | Yes | Yes | No | Yes |
| `strong` | 12 | Yes | Yes | Yes | Yes | Yes |

**Direct PasswordValidator usage:**

```python
from validator import PasswordValidator

# Validate password
password = PasswordValidator.validate("MyP@ssw0rd!", min_strength='strong')

# Check without exception
is_valid = PasswordValidator.is_valid("weak")  # False

# Determine password strength
strength = PasswordValidator.get_strength("MyP@ssw0rd123!")
print(strength)  # "strong", "medium", "weak", or "invalid"

# With custom blacklist
PasswordValidator.validate(
    "MyPassword1!",
    min_strength='strong',
    custom_blacklist={'mypassword'}
)  # Raises error if password matches blacklist
```

### Choices Validation

Restrict values to a predefined list:

```python
class OrderValidator(BaseValidator):
    # String choices
    status: str = Field(
        str,
        choices=['pending', 'processing', 'shipped', 'delivered', 'cancelled']
    )
    
    # Integer choices
    priority: int = Field(int, choices=[1, 2, 3, 4, 5])
    
    # With default
    shipping_method: str = Field(
        str,
        choices=['standard', 'express', 'overnight'],
        default='standard'
    )
```

### Enum Validation

Use Python Enums for type-safe validation:

```python
from enum import Enum

class OrderStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class PaymentMethod(Enum):
    CARD = 1
    PAYPAL = 2
    BANK = 3

class OrderValidator(BaseValidator):
    status: str = Field(str, enum=OrderStatus)
    payment: int = Field(int, enum=PaymentMethod)
    
# Accepts both value and name
order1 = OrderValidator(status="pending", payment=1)
order2 = OrderValidator(status="PENDING", payment="CARD")

# Access as enum instance
print(order1.status)         # OrderStatus.PENDING
print(order1.status.value)   # "pending"

# dict() returns the value, not the enum
print(order1.dict())  # {"status": "pending", "payment": 1}
```

### Nested Validators

Compose validators for complex data structures:

```python
class AddressValidator(BaseValidator):
    street: str = Field(str, max_length=200)
    city: str = Field(str, max_length=100)
    state: str = Field(str, max_length=50, required=False, default="")
    postal_code: str = Field(str, pattern=r'^\d{5}$')
    country: str = Field(str, default="USA")

class ContactValidator(BaseValidator):
    phone: str = Field(str, pattern=r'^\+?\d{10,14}$')
    email: str = Field(str, email=True)

class CompanyValidator(BaseValidator):
    name: str = Field(str, no_empty=True)
    
    # Required nested validator
    headquarters: AddressValidator = Field(AddressValidator)
    
    # Optional nested validator
    billing_address: AddressValidator = Field(AddressValidator, required=False)
    
    # Required contact
    contact: ContactValidator = Field(ContactValidator)

# Usage
company = CompanyValidator(
    name="Acme Corp",
    headquarters={
        "street": "123 Main St",
        "city": "New York",
        "postal_code": "10001"
    },
    contact={
        "phone": "+12025551234",
        "email": "info@acme.com"
    }
)

# Access nested data
print(company.headquarters.city)    # "New York"
print(company.contact.email)        # "info@acme.com"

# Full dict with nested data
print(company.dict())
# {
#     "name": "Acme Corp",
#     "headquarters": {
#         "street": "123 Main St",
#         "city": "New York",
#         "state": "",
#         "postal_code": "10001",
#         "country": "USA"
#     },
#     "contact": {
#         "phone": "+12025551234",
#         "email": "info@acme.com"
#     }
# }
```

### Default Values

**Static defaults:**

```python
class UserValidator(BaseValidator):
    role: str = Field(str, default='user')
    is_active: bool = Field(bool, default=True)
    score: int = Field(int, default=0)
    status: str = Field(str, default='pending')

user = UserValidator()  # All fields will use defaults
print(user.dict())
# {"role": "user", "is_active": True, "score": 0, "status": "pending"}
```

**Dynamic defaults with factory:**

```python
from datetime import datetime
import uuid

class DocumentValidator(BaseValidator):
    # Generate UUID for each instance
    id: str = Field(str, default_factory=lambda: str(uuid.uuid4()))
    
    # Current timestamp
    created_at: str = Field(str, default_factory=lambda: datetime.now().isoformat())
    
    # Empty list (avoid mutable default issues)
    tags: List[str] = Field(List[str], default_factory=list)
    
    # Empty dict
    metadata: Dict[str, Any] = Field(Dict[str, Any], default_factory=dict)

doc1 = DocumentValidator()
doc2 = DocumentValidator()

print(doc1.id != doc2.id)  # True - different UUIDs
print(doc1.created_at)      # "2024-01-15T10:30:45.123456"
```

**Note:** You cannot use both `default` and `default_factory` on the same field.

### List and Dict Validation

```python
from typing import List, Dict, Any

class ArticleValidator(BaseValidator):
    # List of strings
    tags: List[str] = Field(List[str])
    
    # Each string in the list is validated
    categories: List[str] = Field(List[str], max_length=50)  # max_length applies to each item
    
    # Dictionary with any values
    metadata: Dict[str, Any] = Field(Dict[str, Any])

# Lists are validated per-item
article = ArticleValidator(
    tags=["python", "tutorial"],
    categories=["programming", "education"],
    metadata={"author": "John", "views": 100}
)
```

---

## Security Features

### String Sanitization

All string fields are automatically sanitized by default to prevent injection attacks:

```python
class CommentValidator(BaseValidator):
    # Sanitization enabled (default)
    content: str = Field(str, sanitize=True)
    
    # Strict mode (default) - rejects malicious content
    strict_content: str = Field(str, sanitize=True, strict_sanitize=True)
    
    # Non-strict mode - cleans malicious content instead of rejecting
    cleaned_content: str = Field(str, sanitize=True, strict_sanitize=False)
    
    # Disable sanitization (use with caution!)
    raw_content: str = Field(str, sanitize=False)
```

### XSS Prevention

Detects and blocks/removes:

```python
from validator import StringSanitizer

# Script tags
StringSanitizer.sanitize("<script>alert('xss')</script>")
# Raises: ValueError("Script tags are not allowed")

# HTML tags
StringSanitizer.sanitize("<div onclick='evil()'>text</div>")
# Raises: ValueError("HTML tags are not allowed")

# Event handlers
StringSanitizer.sanitize("onclick=alert(1)")
# Raises: ValueError("JavaScript event handlers are not allowed")

# Dangerous protocols
StringSanitizer.sanitize("javascript:alert(1)")
# Raises: ValueError("Dangerous URL protocols are not allowed")

# Non-strict mode (cleans instead of rejecting)
result = StringSanitizer.sanitize("<b>bold</b>", strict=False)
print(result)  # "bold" (tags removed)
```

### SQL Injection Protection

```python
from validator import StringSanitizer

# SQL keywords detected
StringSanitizer.sanitize("'; DROP TABLE users; --")
# Raises: ValueError("Potential SQL injection pattern detected")

# SQL comments
StringSanitizer.sanitize("admin'--")
# Raises: ValueError("Potential SQL injection pattern detected")
```

### Path Traversal Protection

```python
from validator import StringSanitizer

# Path traversal patterns blocked
StringSanitizer.sanitize("../../../etc/passwd")
# Raises: ValueError("Path traversal patterns are not allowed")

StringSanitizer.sanitize("..\\..\\windows\\system32")
# Raises: ValueError("Path traversal patterns are not allowed")
```

### Null Byte Injection Protection

```python
from validator import StringSanitizer

StringSanitizer.sanitize("file.txt\x00.jpg")
# Raises: ValueError("Null bytes are not allowed")
```

### Direct StringSanitizer Usage

```python
from validator import StringSanitizer

# Sanitize a string
clean = StringSanitizer.sanitize(user_input, strict=True)

# Check if a string is safe (without modifying)
is_safe = StringSanitizer.is_safe(user_input)  # Returns True/False
```

---

## API Reference

### BaseValidator

The base class for all validators.

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `__init__(**data)` | - | Create instance and validate data |
| `dict()` | `Dict[str, Any]` | Return validated data as dictionary |
| `__getattr__(name)` | `Any` | Access validated field by name |

**Usage:**

```python
class MyValidator(BaseValidator):
    field1: str
    field2: int = Field(int, min_value=0)

instance = MyValidator(field1="value", field2=10)
print(instance.field1)   # Attribute access
print(instance.dict())   # Dictionary conversion
```

### Field Options

Complete reference of all `Field()` parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `field_type` | `Type` | **required** | Expected type (str, int, float, bool, List, Dict, or validator class) |
| `required` | `bool` | `True` | Whether the field must be provided |
| `no_empty` | `bool` | `False` | Reject empty/whitespace-only strings |
| `min_value` | `float` | `None` | Minimum value for numbers |
| `max_value` | `float` | `None` | Maximum value for numbers |
| `max_length` | `int` | `None` | Maximum string length |
| `sanitize` | `bool` | `True` | Enable string sanitization |
| `strict_sanitize` | `bool` | `True` | Reject (True) vs clean (False) malicious content |
| `email` | `bool` | `False` | Validate as email address |
| `allow_disposable_email` | `bool` | `True` | Allow disposable email domains |
| `pattern` | `str\|Pattern` | `None` | Regex pattern to match |
| `pattern_message` | `str` | `"Value does not match..."` | Custom pattern error message |
| `password` | `bool` | `False` | Enable password validation |
| `password_strength` | `str` | `'medium'` | Password strength: 'weak', 'medium', 'strong' |
| `password_blacklist` | `set` | `None` | Additional passwords to reject |
| `choices` | `List` | `None` | List of allowed values |
| `enum` | `Enum` | `None` | Python Enum class for validation |
| `default` | `Any` | `...` (none) | Static default value |
| `default_factory` | `Callable` | `None` | Function to generate default value |

### ValidationError

Exception raised when validation fails.

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `errors()` | `List[Dict]` | Get list of all validation errors |

**Error dictionary structure:**

```python
{
    "loc": ("body", "field_name"),   # (source, field) or (source, "parent.child")
    "type": "missing|type_error|value_error|extra_forbidden",
    "msg": "Human readable message"
}
```

### StringSanitizer

Static class for string sanitization.

**Methods:**

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `sanitize()` | `value: str, strict: bool = True` | `str` | Sanitize string, raises `ValueError` if strict |
| `is_safe()` | `value: str` | `bool` | Check if string is safe without modifying |

### EmailValidator

Static class for email validation.

**Methods:**

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `validate()` | `email: str, allow_disposable: bool = True, max_length: int = 254` | `str` | Validate and normalize email |
| `is_valid()` | `email: str, allow_disposable: bool = True` | `bool` | Check if email is valid |

### PasswordValidator

Static class for password validation.

**Methods:**

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `validate()` | `password: str, min_strength: str = 'medium', max_length: int = 128, custom_blacklist: set = None` | `str` | Validate password strength |
| `is_valid()` | `password: str, min_strength: str = 'medium'` | `bool` | Check if password is valid |
| `get_strength()` | `password: str` | `str` | Get strength level: 'strong', 'medium', 'weak', 'invalid' |

---

## Complete Examples

### REST API Request Validation

```python
from validator import BaseValidator, Field, ValidationError
from enum import Enum
from typing import List, Optional

class Priority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TaskValidator(BaseValidator):
    title: str = Field(str, no_empty=True, max_length=200)
    description: str = Field(str, max_length=2000, required=False, default="")
    priority: str = Field(str, enum=Priority, default="medium")
    tags: List[str] = Field(List[str], default_factory=list)
    assignee_email: str = Field(str, email=True, required=False)
    due_date: str = Field(
        str,
        pattern=r'^\d{4}-\d{2}-\d{2}$',
        pattern_message="Date must be in YYYY-MM-DD format",
        required=False
    )

def create_task(request_data: dict) -> dict:
    """API endpoint handler for creating a task"""
    try:
        task = TaskValidator(**request_data)
        
        # Save to database...
        return {
            "status": "success",
            "data": task.dict()
        }
        
    except ValidationError as e:
        return {
            "status": "error",
            "errors": [
                {"field": err["loc"][1], "message": err["msg"]}
                for err in e.errors()
            ]
        }

# Example usage
result = create_task({
    "title": "Complete documentation",
    "priority": "high",
    "tags": ["docs", "urgent"]
})
```

### User Registration with Full Validation

```python
from datetime import datetime
from enum import Enum
from typing import Optional

from validator import BaseValidator, Field, ValidationError

class UserRole(Enum):
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"

class AddressValidator(BaseValidator):
    line1: str = Field(str, max_length=100)
    line2: str = Field(str, max_length=100, required=False, default="")
    city: str = Field(str, max_length=50)
    state: str = Field(str, pattern=r'^[A-Z]{2}$', pattern_message="Use 2-letter state code")
    zip_code: str = Field(str, pattern=r'^\d{5}(-\d{4})?$')

class UserRegistrationValidator(BaseValidator):
    username: str = Field(
        str,
        pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$',
        pattern_message="Username: 3-30 chars, start with letter, only letters/numbers/underscore"
    )
    email: str = Field(str, email=True, allow_disposable_email=False)
    password: str = Field(str, password=True, password_strength='strong')
    confirm_password: str = Field(str)  # Validated separately
    
    first_name: str = Field(str, no_empty=True, max_length=50)
    last_name: str = Field(str, no_empty=True, max_length=50)
    
    phone: str = Field(
        str,
        pattern=r'^\+?1?\d{10}$',
        pattern_message="Enter 10-digit phone number",
        required=False
    )
    
    role: str = Field(str, enum=UserRole, default="user")
    
    address: AddressValidator = Field(AddressValidator, required=False)
    
    terms_accepted: bool = Field(bool)
    
    created_at: str = Field(str, default_factory=lambda: datetime.now().isoformat())

def register(data: dict):
    try:
        user = UserRegistrationValidator(**data)
        
        # Additional validation: password confirmation
        if data.get('password') != data.get('confirm_password'):
            return {"success": False, "errors": [{"field": "confirm_password", "message": "Passwords do not match"}]}
        
        # Additional validation: terms must be accepted
        if not user.terms_accepted:
            return {"success": False, "errors": [{"field": "terms_accepted", "message": "You must accept the terms"}]}
        
        return {"success": True, "user": user.dict()}
        
    except ValidationError as e:
        return {
            "success": False,
            "errors": [{"field": err["loc"][1], "message": err["msg"]} for err in e.errors()]
        }
```

### E-commerce Order Validation

```python
from enum import Enum
from typing import List
from decimal import Decimal

from validator import BaseValidator, Field, ValidationError

class PaymentMethod(Enum):
    CARD = "card"
    PAYPAL = "paypal"
    BANK_TRANSFER = "bank_transfer"

class OrderStatus(Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class AddressValidator(BaseValidator):
    name: str = Field(str, no_empty=True)
    street: str = Field(str, max_length=200)
    city: str = Field(str, max_length=100)
    postal_code: str = Field(str, pattern=r'^\d{5}$')
    country: str = Field(str, choices=['US', 'CA', 'UK', 'DE', 'FR'])

class OrderItemValidator(BaseValidator):
    product_id: str = Field(str, pattern=r'^[A-Z]{3}-\d{6}$')
    quantity: int = Field(int, min_value=1, max_value=100)
    unit_price: float = Field(float, min_value=0.01)

class OrderValidator(BaseValidator):
    order_id: str = Field(
        str,
        pattern=r'^ORD-\d{8}-[A-Z]{4}$',
        pattern_message="Order ID format: ORD-12345678-ABCD"
    )
    customer_email: str = Field(str, email=True)
    items: List[dict] = Field(List[dict])  # Validated separately
    shipping_address: AddressValidator = Field(AddressValidator)
    billing_address: AddressValidator = Field(AddressValidator, required=False)
    payment_method: str = Field(str, enum=PaymentMethod)
    status: str = Field(str, enum=OrderStatus, default="pending")
    notes: str = Field(str, max_length=500, required=False, default="")

def validate_order(data: dict):
    errors = []
    
    try:
        order = OrderValidator(**data)
        
        # Validate each order item
        for i, item in enumerate(order.items):
            try:
                OrderItemValidator(**item)
            except ValidationError as e:
                for err in e.errors():
                    errors.append({
                        "field": f"items[{i}].{err['loc'][1]}",
                        "message": err["msg"]
                    })
        
        if errors:
            return {"success": False, "errors": errors}
            
        return {"success": True, "order": order.dict()}
        
    except ValidationError as e:
        return {
            "success": False,
            "errors": [{"field": err["loc"][1], "message": err["msg"]} for err in e.errors()]
        }
```

---

## License

MIT License
