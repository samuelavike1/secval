"""
SecVal - A high-performance, security-focused Python validation library written in Rust.

This package provides:
- BaseValidator: Declarative validation class
- Field: Field descriptor with validation rules
- ValidationError: Exception for validation failures
- StringSanitizer: XSS and injection prevention
- EmailValidator: RFC 5322 email validation
- PasswordValidator: Password strength validation
"""

from secval._secval import (
    StringSanitizer,
    EmailValidator,
    PasswordValidator,
    # Note: ValidationError and Field are implemented in Python for flexibility
    # The Rust module provides: sanitize_string, validate_number, validate_choices
    # but we use the class methods directly for cleaner API
)

from typing import Any, Dict, List, Optional, Type, get_origin, get_args, Union, Callable, Pattern, dataclass_transform
from enum import Enum
import re

__version__ = "0.1.3"
__all__ = [
    "BaseValidator",
    "Field",
    "ValidationError",
    "StringSanitizer",
    "EmailValidator",
    "PasswordValidator",
]


class ValidationError(Exception):
    """Custom validation error exception"""

    def __init__(self, errors: List[Dict[str, Any]]):
        self.errors_list = errors
        super().__init__("Validation failed")

    def errors(self) -> List[Dict[str, Any]]:
        return self.errors_list


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
            # Pattern (regex) validation
            pattern: Optional[Union[str, Pattern]] = None,
            pattern_message: Optional[str] = None,
            # Password validation
            password: bool = False,
            password_strength: str = 'medium',
            password_blacklist: Optional[set] = None,
            # Choices/Enum validation
            choices: Optional[List[Any]] = None,
            enum: Optional[Type[Enum]] = None,
            # Default values
            default: Any = ...,
            default_factory: Optional[Callable[[], Any]] = None,
    ):
        self.field_type = field_type
        self.required = required
        self.no_empty = no_empty
        self.min_value = min_value
        self.max_value = max_value
        self.sanitize = sanitize
        self.strict_sanitize = strict_sanitize
        self.max_length = max_length
        self.email = email
        self.allow_disposable_email = allow_disposable_email

        # Pattern validation
        if pattern is not None:
            self.pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
            self.pattern_str = pattern if isinstance(pattern, str) else pattern.pattern
        else:
            self.pattern = None
            self.pattern_str = None
        self.pattern_message = pattern_message or "Value does not match required pattern"

        # Password validation
        self.password = password
        self.password_strength = password_strength
        self.password_blacklist = list(password_blacklist) if password_blacklist else None

        # Choices/Enum validation
        self.choices = choices
        self.enum = enum

        # Default values
        self.default = default
        self.default_factory = default_factory

        # Validation: can't have both default and default_factory
        if default is not ... and default_factory is not None:
            raise ValueError("Cannot specify both 'default' and 'default_factory'")

    def has_default(self) -> bool:
        """Check if field has a default value"""
        return self.default is not ... or self.default_factory is not None

    def get_default(self) -> Any:
        """Get the default value for this field"""
        if self.default_factory is not None:
            return self.default_factory()
        if self.default is not ...:
            return self.default
        raise ValueError("No default value available")

@dataclass_transform(kw_only_default=True, field_specifiers=(Field,))
class ValidatorMeta(type):
    """Metaclass to collect field definitions"""

    def __new__(mcs, name, bases, attrs):
        fields = {}
        annotations = attrs.get('__annotations__', {})

        # Inherit fields from parent classes
        for base in bases:
            if hasattr(base, '_fields'):
                fields.update(base._fields)

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
    """Base validator class with security features - powered by Rust"""
    _fields: Dict[str, Field] = {}

    def __init__(self, **data):
        self._data = {}
        self._validate(data)

    def _validate(self, data: Dict[str, Any]):
        """Validate input data against field definitions"""
        errors = []

        for field_name, field_def in self._fields.items():
            value = data.get(field_name)

            # Handle missing values with defaults
            if value is None:
                if field_def.has_default():
                    default_value = field_def.get_default()
                    # Apply enum conversion to default values too
                    if field_def.enum is not None:
                        try:
                            default_value = field_def.enum(default_value)
                        except ValueError:
                            try:
                                default_value = field_def.enum[default_value]
                            except KeyError:
                                pass  # Keep original default if conversion fails
                    self._data[field_name] = default_value
                    continue
                elif field_def.required:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "missing",
                        "msg": "Field required",
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

            # String-specific validations (using Rust functions)
            if isinstance(validated_value, str):
                try:
                    if field_def.password:
                        validated_value = PasswordValidator.validate(
                            validated_value,
                            field_def.password_strength,
                            field_def.max_length or 128,
                            field_def.password_blacklist
                        )
                    elif field_def.email:
                        validated_value = EmailValidator.validate(
                            validated_value,
                            field_def.allow_disposable_email,
                            field_def.max_length or 254
                        )
                    else:
                        # Sanitization (using Rust)
                        if field_def.sanitize:
                            validated_value = StringSanitizer.sanitize(
                                validated_value,
                                field_def.strict_sanitize
                            )

                        # Pattern validation
                        if field_def.pattern is not None:
                            if not field_def.pattern.match(validated_value):
                                raise ValueError(field_def.pattern_message)

                        # Length validation
                        if field_def.max_length is not None and len(validated_value) > field_def.max_length:
                            raise ValueError(f"String length must be at most {field_def.max_length}")

                        # No empty validation
                        if field_def.no_empty and not validated_value.strip():
                            raise ValueError("String cannot be empty")

                except ValueError as e:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": str(e),
                    })
                    continue

            # Choices validation
            if field_def.choices is not None:
                if validated_value not in field_def.choices:
                    choices_str = ', '.join(repr(c) for c in field_def.choices)
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": f"Value must be one of: {choices_str}",
                    })
                    continue

            # Enum validation
            if field_def.enum is not None:
                try:
                    validated_value = field_def.enum(validated_value)
                except ValueError:
                    try:
                        validated_value = field_def.enum[validated_value]
                    except KeyError:
                        valid_values = [e.value for e in field_def.enum]
                        valid_names = [e.name for e in field_def.enum]
                        errors.append({
                            "loc": ("body", field_name),
                            "type": "value_error",
                            "msg": f"Invalid enum value. Valid values: {valid_values}, Valid names: {valid_names}",
                        })
                        continue

            # Numeric range validation (using Rust)
            if isinstance(validated_value, (int, float)) and not isinstance(validated_value, bool):
                try:
                    if field_def.min_value is not None and validated_value < field_def.min_value:
                        raise ValueError(f"Value must be at least {field_def.min_value}")
                    if field_def.max_value is not None and validated_value > field_def.max_value:
                        raise ValueError(f"Value must be at most {field_def.max_value}")
                except ValueError as e:
                    errors.append({
                        "loc": ("body", field_name),
                        "type": "value_error",
                        "msg": str(e),
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
                non_none_types = [t for t in args if t is not type(None)]
                if non_none_types:
                    return self._validate_type(value, non_none_types[0], field_name, field_def)

        # Handle List types
        if origin is list:
            if not isinstance(value, list):
                raise ValueError(f"Expected list, got {type(value).__name__}")
            item_type = get_args(expected_type)[0] if get_args(expected_type) else Any
            return [self._validate_type(item, item_type, f"{field_name}[{i}]", field_def) for i, item in enumerate(value)]

        # Handle Dict types
        if origin is dict:
            if not isinstance(value, dict):
                raise ValueError(f"Expected dict, got {type(value).__name__}")
            if field_def and field_def.sanitize:
                sanitized_dict = {}
                for k, v in value.items():
                    if isinstance(k, str):
                        k = StringSanitizer.sanitize(k, field_def.strict_sanitize)
                    if isinstance(v, str):
                        v = StringSanitizer.sanitize(v, field_def.strict_sanitize)
                    sanitized_dict[k] = v
                return sanitized_dict
            return value

        # Basic type validation
        if expected_type is str:
            if not isinstance(value, str):
                raise ValueError(f"Expected string, got {type(value).__name__}")
            return value

        elif expected_type is int:
            if isinstance(value, bool):
                raise ValueError("Expected integer, got boolean")
            if not isinstance(value, int):
                raise ValueError(f"Expected integer, got {type(value).__name__}")
            return value

        elif expected_type is float:
            if isinstance(value, bool):
                raise ValueError("Expected float, got boolean")
            if not isinstance(value, (int, float)):
                raise ValueError(f"Expected float, got {type(value).__name__}")
            return float(value)

        elif expected_type is bool:
            if not isinstance(value, bool):
                raise ValueError(f"Expected boolean, got {type(value).__name__}")
            return value

        # Handle nested validators
        elif isinstance(expected_type, type) and issubclass(expected_type, BaseValidator):
            if not isinstance(value, dict):
                raise ValueError(f"Expected object/dict for nested validator, got {type(value).__name__}")
            try:
                nested_instance = expected_type(**value)
                return nested_instance
            except ValidationError as e:
                nested_errors = []
                for error in e.errors():
                    loc = error.get("loc", ())
                    if len(loc) >= 2:
                        new_loc = (loc[0], f"{field_name}.{loc[1]}")
                    else:
                        new_loc = ("body", field_name)
                    nested_errors.append({**error, "loc": new_loc})
                raise ValidationError(nested_errors)

        return value

    def dict(self) -> Dict[str, Any]:
        """Return validated data as dictionary"""
        result = {}
        for key, value in self._data.items():
            if isinstance(value, BaseValidator):
                result[key] = value.dict()
            elif isinstance(value, list):
                result[key] = [
                    item.dict() if isinstance(item, BaseValidator) else item
                    for item in value
                ]
            elif isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result

    def __getattr__(self, name: str) -> Any:
        """Allow attribute access to validated fields"""
        if name.startswith('_'):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
