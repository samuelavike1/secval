import re
from typing import Any, Dict, List, Optional, Type, get_origin, get_args, Union
from html import escape


class ValidationError(Exception):
    """Custom validation error exception"""

    def __init__(self, errors: List[Dict[str, Any]]):
        self.errors_list = errors
        super().__init__("Validation failed")

    def errors(self) -> List[Dict[str, Any]]:
        return self.errors_list


class StringSanitizer:
    """Handles string sanitization to prevent injection attacks"""

    # Patterns for detecting malicious content
    HTML_TAG_PATTERN = re.compile(r'<[^>]*>', re.IGNORECASE)
    SCRIPT_PATTERN = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
    EVENT_HANDLER_PATTERN = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
    JAVASCRIPT_PROTOCOL = re.compile(r'javascript:', re.IGNORECASE)
    DATA_PROTOCOL = re.compile(r'data:', re.IGNORECASE)
    VBSCRIPT_PROTOCOL = re.compile(r'vbscript:', re.IGNORECASE)

    # SQL injection patterns
    SQL_KEYWORDS = re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE|CAST|CONVERT)\b)",
        re.IGNORECASE
    )
    SQL_COMMENT = re.compile(r'(--|#|/\*|\*/)')

    # Path traversal patterns
    PATH_TRAVERSAL = re.compile(r'\.\.[/\\]')

    # Null byte injection
    NULL_BYTE = re.compile(r'\x00')

    @classmethod
    def sanitize(cls, value: str, strict: bool = True) -> str:
        """
        Sanitize a string to prevent injection attacks

        Args:
            value: String to sanitize
            strict: If True, reject strings with malicious patterns.
                   If False, attempt to clean them.

        Returns:
            Sanitized string

        Raises:
            ValueError: If strict=True and malicious content detected
        """
        if not isinstance(value, str):
            return value

        original_value = value

        # Check for null bytes
        if cls.NULL_BYTE.search(value):
            if strict:
                raise ValueError("Null bytes are not allowed")
            value = cls.NULL_BYTE.sub('', value)

        # Check for path traversal
        if cls.PATH_TRAVERSAL.search(value):
            if strict:
                raise ValueError("Path traversal patterns are not allowed")
            value = cls.PATH_TRAVERSAL.sub('', value)

        # Check for script tags
        if cls.SCRIPT_PATTERN.search(value):
            if strict:
                raise ValueError("Script tags are not allowed")
            value = cls.SCRIPT_PATTERN.sub('', value)

        # Check for HTML tags
        if cls.HTML_TAG_PATTERN.search(value):
            if strict:
                raise ValueError("HTML tags are not allowed")
            # Remove all HTML tags
            value = cls.HTML_TAG_PATTERN.sub('', value)

        # Check for event handlers (onclick, onerror, etc.)
        if cls.EVENT_HANDLER_PATTERN.search(value):
            if strict:
                raise ValueError("JavaScript event handlers are not allowed")
            value = cls.EVENT_HANDLER_PATTERN.sub('', value)

        # Check for dangerous protocols
        if (cls.JAVASCRIPT_PROTOCOL.search(value) or
                cls.DATA_PROTOCOL.search(value) or
                cls.VBSCRIPT_PROTOCOL.search(value)):
            if strict:
                raise ValueError("Dangerous URL protocols are not allowed")
            value = cls.JAVASCRIPT_PROTOCOL.sub('', value)
            value = cls.DATA_PROTOCOL.sub('', value)
            value = cls.VBSCRIPT_PROTOCOL.sub('', value)

        # Check for SQL injection patterns
        if cls.SQL_KEYWORDS.search(value) or cls.SQL_COMMENT.search(value):
            if strict:
                raise ValueError("Potential SQL injection pattern detected")
            # For non-strict mode, we escape but don't remove
            # (some legitimate text might contain these words)
            pass

        # HTML escape special characters as additional protection
        value = escape(value)

        return value

    @classmethod
    def is_safe(cls, value: str) -> bool:
        """Check if a string is safe without modifying it"""
        try:
            cls.sanitize(value, strict=True)
            return True
        except ValueError:
            return False


class EmailValidator:
    """Handles email validation"""

    # RFC 5322 compliant email pattern (simplified but robust)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )

    # Common disposable email domains
    DISPOSABLE_DOMAINS = {
        'tempmail.com', 'throwaway.email', '10minutemail.com', 'guerrillamail.com',
        'mailinator.com', 'maildrop.cc', 'temp-mail.org', 'yopmail.com'
    }

    @classmethod
    def validate(cls, email: str, allow_disposable: bool = True, max_length: int = 254) -> str:
        """
        Validate an email address

        Args:
            email: Email address to validate
            allow_disposable: Whether to allow disposable email addresses
            max_length: Maximum email length (RFC 5321 limit is 254)

        Returns:
            Normalized email address (lowercase)

        Raises:
            ValueError: If email is invalid
        """
        if not isinstance(email, str):
            raise ValueError("Email must be a string")

        # Normalize: strip whitespace and convert to lowercase
        email = email.strip().lower()

        # Check length
        if len(email) > max_length:
            raise ValueError(f"Email address is too long (max {max_length} characters)")

        if len(email) == 0:
            raise ValueError("Email address cannot be empty")

        # Check basic format
        if not cls.EMAIL_PATTERN.match(email):
            raise ValueError("Invalid email address format")

        # Split into local and domain parts
        try:
            local, domain = email.rsplit('@', 1)
        except ValueError:
            raise ValueError("Invalid email address format")

        # Validate local part
        if len(local) == 0 or len(local) > 64:
            raise ValueError("Email local part must be between 1 and 64 characters")

        # Check for consecutive dots
        if '..' in local or '..' in domain:
            raise ValueError("Email address cannot contain consecutive dots")

        # Local part cannot start or end with a dot
        if local.startswith('.') or local.endswith('.'):
            raise ValueError("Email local part cannot start or end with a dot")

        # Validate domain part
        if len(domain) == 0 or len(domain) > 253:
            raise ValueError("Email domain must be between 1 and 253 characters")

        # Domain must have at least one dot
        if '.' not in domain:
            raise ValueError("Email domain must contain at least one dot")

        # Check each domain label
        labels = domain.split('.')
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                raise ValueError("Each domain label must be between 1 and 63 characters")
            if label.startswith('-') or label.endswith('-'):
                raise ValueError("Domain labels cannot start or end with a hyphen")

        # Check TLD (top-level domain) is at least 2 characters
        if len(labels[-1]) < 2:
            raise ValueError("Top-level domain must be at least 2 characters")

        # Check for disposable domains
        if not allow_disposable and domain in cls.DISPOSABLE_DOMAINS:
            raise ValueError("Disposable email addresses are not allowed")

        return email

    @classmethod
    def is_valid(cls, email: str, allow_disposable: bool = True) -> bool:
        """Check if an email is valid without raising an exception"""
        try:
            cls.validate(email, allow_disposable=allow_disposable)
            return True
        except ValueError:
            return False


class Field:
    """Field descriptor for validation rules"""

    def __init__(
            self,
            field_type: Type,
            required: bool = True,
            no_empty: bool = False,
            min_value: Optional[float] = None,
            max_value: Optional[float] = None,
            sanitize: bool = True,
            strict_sanitize: bool = True,
            max_length: Optional[int] = None,
            email: bool = False,
            allow_disposable_email: bool = True,
    ):
        self.field_type = field_type
        self.required = required
        self.no_empty = no_empty
        self.min_value = min_value
        self.max_value = max_value
        self.sanitize = sanitize  # Whether to sanitize strings
        self.strict_sanitize = strict_sanitize  # Reject vs clean malicious content
        self.max_length = max_length  # Maximum string length
        self.email = email  # Whether to validate as email
        self.allow_disposable_email = allow_disposable_email  # Allow disposable emails


class ValidatorMeta(type):
    """Metaclass to collect field definitions"""

    def __new__(mcs, name, bases, attrs):
        fields = {}
        annotations = attrs.get('__annotations__', {})

        for field_name, field_type in annotations.items():
            if field_name.startswith('_'):
                continue

            # Check if there's a Field instance defined
            field_def = attrs.get(field_name)
            if isinstance(field_def, Field):
                fields[field_name] = field_def
                # Remove the Field instance from class attributes
                del attrs[field_name]
            else:
                # Create default Field from annotation
                fields[field_name] = Field(field_type=field_type, required=True)

        attrs['_fields'] = fields
        return super().__new__(mcs, name, bases, attrs)


class BaseValidator(metaclass=ValidatorMeta):
    """Base validator class with security features"""
    _fields: Dict[str, Field] = {}

    def __init__(self, **data):
        self._data = {}
        self._validate(data)

    def _validate(self, data: Dict[str, Any]):
        """Validate input data against field definitions"""
        errors = []

        for field_name, field_def in self._fields.items():
            value = data.get(field_name)

            # Check required fields
            if value is None:
                if field_def.required:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "missing",
                        "msg": f"Field required",
                    })
                continue

            # Type validation
            try:
                validated_value = self._validate_type(
                    value, field_def.field_type, field_name, field_def
                )
            except ValueError as e:
                errors.append({
                    "loc": ("body", field_name),
                    "type": "type_error",
                    "msg": str(e),
                })
                continue

            # String-specific validations
            if isinstance(validated_value, str):
                # Email validation
                if field_def.email:
                    try:
                        validated_value = EmailValidator.validate(
                            validated_value,
                            allow_disposable=field_def.allow_disposable_email,
                            max_length=field_def.max_length or 254
                        )
                    except ValueError as e:
                        errors.append({
                            "loc": ("body", field_name),
                            "type": "value_error",
                            "msg": str(e),
                        })
                        continue

                # Length validation (skip if email validation already checked)
                if not field_def.email and field_def.max_length is not None and len(
                        validated_value) > field_def.max_length:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": f"String length must be at most {field_def.max_length}",
                    })
                    continue

                # No empty string validation
                if field_def.no_empty and not validated_value.strip():
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": "String cannot be empty",
                    })
                    continue

            # Numeric range validation
            if isinstance(validated_value, (int, float)):
                if field_def.min_value is not None and validated_value < field_def.min_value:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": f"Value must be at least {field_def.min_value}",
                    })
                    continue

                if field_def.max_value is not None and validated_value > field_def.max_value:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": f"Value must be at most {field_def.max_value}",
                    })
                    continue

            self._data[field_name] = validated_value

        # Check for extra fields
        for key in data:
            if key not in self._fields:
                errors.append({
                    "loc": ("body", key),
                    "type": "extra_forbidden",
                    "msg": "Extra inputs are not permitted",
                })

        if errors:
            raise ValidationError(errors)

    def _validate_type(self, value: Any, expected_type: Type, field_name: str, field_def: Field = None) -> Any:
        """Validate and convert value to expected type"""
        origin = get_origin(expected_type)

        # Handle Optional types
        if origin is Union:
            args = get_args(expected_type)
            if type(None) in args:
                if value is None:
                    return None
                # Try to validate against non-None type
                non_none_types = [t for t in args if t is not type(None)]
                if non_none_types:
                    return self._validate_type(value, non_none_types[0], field_name, field_def)

        # Handle List types
        if origin is list:
            if not isinstance(value, list):
                raise ValueError(f"Expected list, got {type(value).__name__}")
            item_type = get_args(expected_type)[0] if get_args(expected_type) else Any
            return [self._validate_type(item, item_type, f"{field_name}[{i}]", field_def) for i, item in
                    enumerate(value)]

        # Handle Dict types
        if origin is dict:
            if not isinstance(value, dict):
                raise ValueError(f"Expected dict, got {type(value).__name__}")
            # Sanitize dict keys and string values
            if field_def and field_def.sanitize:
                sanitized_dict = {}
                for k, v in value.items():
                    # Sanitize keys
                    if isinstance(k, str):
                        k = StringSanitizer.sanitize(k, strict=field_def.strict_sanitize)
                    # Sanitize string values
                    if isinstance(v, str):
                        v = StringSanitizer.sanitize(v, strict=field_def.strict_sanitize)
                    sanitized_dict[k] = v
                return sanitized_dict
            return value

        # Basic type validation
        if expected_type is str:
            if not isinstance(value, str):
                raise ValueError(f"Expected string, got {type(value).__name__}")

            # Apply sanitization if enabled (but not for email fields - emails are validated separately)
            if field_def and field_def.sanitize and not field_def.email:
                value = StringSanitizer.sanitize(value, strict=field_def.strict_sanitize)

            return value

        elif expected_type is int:
            if isinstance(value, bool):
                raise ValueError(f"Expected integer, got boolean")
            if not isinstance(value, int):
                raise ValueError(f"Expected integer, got {type(value).__name__}")
            return value

        elif expected_type is float:
            if isinstance(value, bool):
                raise ValueError(f"Expected float, got boolean")
            if not isinstance(value, (int, float)):
                raise ValueError(f"Expected float, got {type(value).__name__}")
            return float(value)

        elif expected_type is bool:
            if not isinstance(value, bool):
                raise ValueError(f"Expected boolean, got {type(value).__name__}")
            return value

        return value

    def dict(self) -> Dict[str, Any]:
        """Return validated data as dictionary"""
        return self._data.copy()

    def __getattr__(self, name: str) -> Any:
        """Allow attribute access to validated fields"""
        if name.startswith('_'):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")