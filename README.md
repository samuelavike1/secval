# SecVal 🦀⚡

A **high-performance**, **security-focused** Python validation library written in **Rust** using PyO3.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- ⚡ **Rust-powered performance** - Core validation logic written in Rust
- 🛡️ **Security-first** - Built-in XSS, SQL injection, and path traversal protection
- 📧 **Email validation** - RFC 5322 compliant with disposable email blocking
- 🔐 **Password strength** - Configurable strength levels (weak/medium/strong)
- ✅ **Pattern matching** - Regex validation with custom error messages
- 📦 **Choices & Enums** - Restrict values to allowed options
- 🪆 **Nested validators** - Compose complex data structures
- 🎯 **Default values** - Static defaults and factory functions
- 🔍 **Type-safe** - Full type checker support with function overloads

## Installation

```bash
pip install secval
```

## Quick Start

```python
from secval import BaseValidator, Field, ValidationError

class UserValidator(BaseValidator):
    name: str = Field(no_empty=True, max_length=100)
    email: str = Field(email=True)
    age: int = Field(min_value=0, max_value=120)

try:
    user = UserValidator(
        name="John Doe",
        email="john@example.com",
        age=30
    )
    print(user.dict())  # {'name': 'John Doe', 'email': 'john@example.com', 'age': 30}
except ValidationError as e:
    for error in e.errors():
        print(f"Field: {error['loc']}, Error: {error['msg']}")
```

## Table of Contents

- [Error Handling](#error-handling)
- [Validation Features](#validation-features)
  - [Type Validation](#type-validation)
  - [String Constraints](#string-constraints)
  - [Numeric Range](#numeric-range)
  - [Email Validation](#email-validation)
  - [Pattern (Regex)](#pattern-regex-validation)
  - [Password Validation](#password-validation)
  - [Choices](#choices-validation)
  - [Enum Validation](#enum-validation)
  - [Nested Validators](#nested-validators)
  - [Default Values](#default-values)
- [Security Features](#security-features)
- [API Reference](#api-reference)
- [Performance](#performance)

---

## Error Handling

### Error Structure

```python
{
    "loc": ("body", "field_name"),    # Location tuple
    "type": "missing|type_error|value_error|extra_forbidden",
    "msg": "Human readable message"
}
```

### Complete Example

```python
from secval import BaseValidator, Field, ValidationError

class ProductValidator(BaseValidator):
    name: str = Field(no_empty=True)
    price: float = Field(min_value=0.01)

def create_product(data: dict) -> dict:
    try:
        product = ProductValidator(**data)
        return {"success": True, "data": product.dict()}
    except ValidationError as e:
        return {
            "success": False,
            "errors": [
                {"field": err["loc"][1], "message": err["msg"]}
                for err in e.errors()
            ]
        }

# Test with invalid data
result = create_product({"name": "", "price": -10})
# {
#     "success": False,
#     "errors": [
#         {"field": "name", "message": "String cannot be empty"},
#         {"field": "price", "message": "Value must be at least 0.01"}
#     ]
# }
```

---

## Validation Features

### Type Validation

```python
from typing import List, Dict, Optional, Any

class DataValidator(BaseValidator):
    text: str                    # String (required)
    count: int                   # Integer
    price: float                 # Float (accepts int too)
    active: bool                 # Boolean
    items: List[str]             # List of strings
    metadata: Dict[str, Any]     # Dictionary
    maybe_text: Optional[str] = Field(default=None)  # Optional
```

### String Constraints

```python
class ProfileValidator(BaseValidator):
    username: str = Field(max_length=30)
    bio: str = Field(no_empty=True)
    title: str = Field(max_length=100, no_empty=True)
```

### Numeric Range

```python
class ProductValidator(BaseValidator):
    quantity: int = Field(min_value=0)
    rating: float = Field(min_value=0.0, max_value=5.0)
```

### Email Validation

```python
class ContactValidator(BaseValidator):
    email: str = Field(email=True)
    work_email: str = Field(email=True, allow_disposable_email=False)
```

**Direct usage:**

```python
from secval import EmailValidator

email = EmailValidator.validate("  John@Example.COM  ")
print(email)  # "john@example.com"

is_valid = EmailValidator.is_valid("test@example.com")  # True
```

### Pattern (Regex) Validation

```python
class FormValidator(BaseValidator):
    phone: str = Field(
        pattern=r'^\+?1?\d{10}$',
        pattern_message="Invalid phone number"
    )
    username: str = Field(
        pattern=r'^[a-zA-Z][a-zA-Z0-9_]{2,29}$',
        pattern_message="Username: 3-30 chars, start with letter"
    )
    postal_code: str = Field(
        pattern=r'^\d{5}(-\d{4})?$',
        pattern_message="Invalid ZIP code"
    )
```

### Password Validation

Three strength levels:

| Level | Min Length | Upper | Lower | Digit | Special | Common Check |
|-------|------------|-------|-------|-------|---------|--------------|
| `weak` | 6 | ❌ | ❌ | ❌ | ❌ | ❌ |
| `medium` | 8 | ✅ | ✅ | ✅ | ❌ | ✅ |
| `strong` | 12 | ✅ | ✅ | ✅ | ✅ | ✅ |

```python
class RegistrationValidator(BaseValidator):
    password: str = Field(
        password=True,
        password_strength='strong',
        password_blacklist={'companyname'}
    )
```

**Direct usage:**

```python
from secval import PasswordValidator

strength = PasswordValidator.get_strength("MyP@ssw0rd!")  # "strong"
is_valid = PasswordValidator.is_valid("weak", "strong")   # False
```

### Choices Validation

```python
class OrderValidator(BaseValidator):
    status: str = Field(choices=['pending', 'processing', 'shipped', 'delivered'])
    priority: int = Field(choices=[1, 2, 3, 4, 5])
```

### Enum Validation

```python
from enum import Enum

class OrderStatus(Enum):
    PENDING = "pending"
    SHIPPED = "shipped"
    DELIVERED = "delivered"

class OrderValidator(BaseValidator):
    status: str = Field(enum=OrderStatus)

# Accepts both value and name
order = OrderValidator(status="pending")   # or status="PENDING"
print(order.status)        # OrderStatus.PENDING
print(order.dict())        # {"status": "pending"}
```

### Nested Validators

```python
from typing import Optional, Any

class AddressValidator(BaseValidator):
    street: str = Field(max_length=200)
    city: str = Field(max_length=100)
    postal_code: str = Field(pattern=r'^\d{5}$')

class UserValidator(BaseValidator):
    name: str
    address: AddressValidator | dict[str, Any]  # Pass dict, gets validated
    billing: Optional[AddressValidator | dict[str, Any]] = Field(default=None)

user = UserValidator(
    name="John",
    address={"street": "123 Main", "city": "NYC", "postal_code": "10001"}
)

print(user.address.city)  # "NYC"
print(user.dict())        # Nested dicts included
```

Nested errors include full path:
```python
# Error: ("body", "address.postal_code")
```

### Default Values

**Static defaults:**

```python
class UserValidator(BaseValidator):
    role: str = Field(default='user')
    is_active: bool = Field(default=True)
```

**Dynamic defaults:**

```python
from datetime import datetime

class DocumentValidator(BaseValidator):
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = Field(default_factory=list)
```

---

## Security Features

All strings are **automatically sanitized** to prevent injection attacks:

### XSS Prevention

```python
from secval import StringSanitizer

# Blocked (raises ValueError)
StringSanitizer.sanitize("<script>alert('xss')</script>")
StringSanitizer.sanitize("<div onclick='evil()'>")
StringSanitizer.sanitize("javascript:alert(1)")
```

### SQL Injection Protection

```python
# Blocked (raises ValueError)
StringSanitizer.sanitize("'; DROP TABLE users; --")
```

### Path Traversal Protection

```python
# Blocked (raises ValueError)
StringSanitizer.sanitize("../../../etc/passwd")
```

### Non-strict Mode

```python
# Clean instead of reject
result = StringSanitizer.sanitize("<b>bold</b>", strict=False)
print(result)  # "bold"
```

---

## API Reference

### Field Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `required` | `bool` | `True` | Field is required |
| `no_empty` | `bool` | `False` | Reject empty strings |
| `min_value` | `float` | `None` | Minimum for numbers |
| `max_value` | `float` | `None` | Maximum for numbers |
| `max_length` | `int` | `None` | Max string length |
| `sanitize` | `bool` | `True` | Enable sanitization |
| `strict_sanitize` | `bool` | `True` | Reject vs clean |
| `email` | `bool` | `False` | Email validation |
| `allow_disposable_email` | `bool` | `True` | Allow temp emails |
| `pattern` | `str` | `None` | Regex pattern |
| `pattern_message` | `str` | `"..."` | Pattern error msg |
| `password` | `bool` | `False` | Password validation |
| `password_strength` | `str` | `'medium'` | weak/medium/strong |
| `password_blacklist` | `set` | `None` | Blocked passwords |
| `choices` | `List` | `None` | Allowed values |
| `enum` | `Enum` | `None` | Enum class |
| `default` | `Any` | - | Default value |
| `default_factory` | `Callable` | `None` | Default generator |

> **Note:** Field type is inferred from the annotation - no need to pass it explicitly.

### Utility Classes

```python
# StringSanitizer
StringSanitizer.sanitize(value, strict=True) -> str
StringSanitizer.is_safe(value) -> bool

# EmailValidator
EmailValidator.validate(email, allow_disposable=True, max_length=254) -> str
EmailValidator.is_valid(email, allow_disposable=True) -> bool

# PasswordValidator
PasswordValidator.validate(password, min_strength="medium", max_length=128, custom_blacklist=None) -> str
PasswordValidator.is_valid(password, min_strength="medium") -> bool
PasswordValidator.get_strength(password) -> str  # "strong"|"medium"|"weak"|"invalid"
```

---

## Performance

SecVal is powered by Rust, providing:

- **10-100x faster** string sanitization vs pure Python regex
- **Zero-copy** string handling where possible
- **Compiled regex patterns** cached at startup
- **Minimal memory allocations**

---

## Development

### Prerequisites

- Python 3.11+
- Rust 1.70+
- maturin

### Setup

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repo
git clone https://github.com/samuelavike1/secval.git
cd secval

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dev dependencies
pip install maturin pytest

# Build and install in dev mode
maturin develop

# Run tests
pytest tests/ -v
```

### Building Wheels

```bash
# Build release wheel
maturin build --release

# Build for all platforms (requires Docker)
maturin build --release --target x86_64-unknown-linux-gnu
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Contributing

Contributions welcome! Please read the contributing guidelines first.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a pull request
