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

from secval._secval import (  # pyright: ignore[reportPrivateUsage]
    StringSanitizer,
    EmailValidator,
    PasswordValidator,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Type,
    get_origin,
    get_args,
    Union,
    Callable,
    Pattern,
    dataclass_transform,
    TypeVar,
    overload,
)
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

T = TypeVar("T")


class ValidationError(Exception):
    """Custom validation error exception"""

    def __init__(self, errors: List[Dict[str, Any]]):
        self.errors_list = errors
        super().__init__("Validation failed")

    def errors(self) -> List[Dict[str, Any]]:
        return self.errors_list


# Sentinel for missing default value
_MISSING: Any = object()


# Overload 1: Field with explicit default value - returns T
@overload
def Field(
    *,
    required: bool = ...,
    no_empty: bool = ...,
    min_value: Optional[float] = ...,
    max_value: Optional[float] = ...,
    sanitize: bool = ...,
    strict_sanitize: bool = ...,
    max_length: Optional[int] = ...,
    email: bool = ...,
    allow_disposable_email: bool = ...,
    pattern: Optional[Union[str, Pattern]] = ...,
    pattern_message: Optional[str] = ...,
    password: bool = ...,
    password_strength: str = ...,
    password_blacklist: Optional[set] = ...,
    choices: Optional[List[Any]] = ...,
    enum: Optional[Type[Enum]] = ...,
    default: T,
    default_factory: None = ...,
) -> T: ...


# Overload 2: Field with default_factory - returns T
@overload
def Field(
    *,
    required: bool = ...,
    no_empty: bool = ...,
    min_value: Optional[float] = ...,
    max_value: Optional[float] = ...,
    sanitize: bool = ...,
    strict_sanitize: bool = ...,
    max_length: Optional[int] = ...,
    email: bool = ...,
    allow_disposable_email: bool = ...,
    pattern: Optional[Union[str, Pattern]] = ...,
    pattern_message: Optional[str] = ...,
    password: bool = ...,
    password_strength: str = ...,
    password_blacklist: Optional[set] = ...,
    choices: Optional[List[Any]] = ...,
    enum: Optional[Type[Enum]] = ...,
    default: None = ...,
    default_factory: Callable[[], T],
) -> T: ...


# Overload 3: Field with no default (required) - returns Any (type comes from annotation)
@overload
def Field(
    *,
    required: bool = ...,
    no_empty: bool = ...,
    min_value: Optional[float] = ...,
    max_value: Optional[float] = ...,
    sanitize: bool = ...,
    strict_sanitize: bool = ...,
    max_length: Optional[int] = ...,
    email: bool = ...,
    allow_disposable_email: bool = ...,
    pattern: Optional[Union[str, Pattern]] = ...,
    pattern_message: Optional[str] = ...,
    password: bool = ...,
    password_strength: str = ...,
    password_blacklist: Optional[set] = ...,
    choices: Optional[List[Any]] = ...,
    enum: Optional[Type[Enum]] = ...,
) -> Any: ...


def Field(
    *,
    required: bool = True,
    no_empty: bool = False,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
    sanitize: bool = True,
    strict_sanitize: bool = True,
    max_length: Optional[int] = None,
    email: bool = False,
    allow_disposable_email: bool = True,
    pattern: Optional[Union[str, Pattern]] = None,
    pattern_message: Optional[str] = None,
    password: bool = False,
    password_strength: str = "medium",
    password_blacklist: Optional[set] = None,
    choices: Optional[List[Any]] = None,
    enum: Optional[Type[Enum]] = None,
    default: Any = _MISSING,
    default_factory: Optional[Callable[[], Any]] = None,
) -> Any:
    """
    Field descriptor for validation rules.

    Usage:
        class MyValidator(BaseValidator):
            # Required fields - just use annotation or Field() for constraints
            name: str = Field(max_length=100)
            email: str = Field(email=True)
            active: bool  # No Field() needed for simple required fields

            # Optional fields - use default=None
            nickname: Optional[str] = Field(default=None)

            # Fields with other defaults
            role: str = Field(default="user")
            tags: List[str] = Field(default_factory=list)

            # Nested validators - use Union with dict for type checker
            address: Optional[AddressValidator | dict[str, Any]] = Field(default=None)
    """
    # If required=False and no default specified, use None as default
    actual_default = default
    if not required and default is _MISSING and default_factory is None:
        actual_default = None

    return FieldInfo(
        required=required,
        no_empty=no_empty,
        min_value=min_value,
        max_value=max_value,
        sanitize=sanitize,
        strict_sanitize=strict_sanitize,
        max_length=max_length,
        email=email,
        allow_disposable_email=allow_disposable_email,
        pattern=pattern,
        pattern_message=pattern_message,
        password=password,
        password_strength=password_strength,
        password_blacklist=password_blacklist,
        choices=choices,
        enum=enum,
        default=actual_default,
        default_factory=default_factory,
    )


class FieldInfo:
    """Internal class holding field configuration. Use Field() function to create."""

    def __init__(
        self,
        *,
        required: bool = True,
        no_empty: bool = False,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        sanitize: bool = True,
        strict_sanitize: bool = True,
        max_length: Optional[int] = None,
        email: bool = False,
        allow_disposable_email: bool = True,
        pattern: Optional[Union[str, Pattern]] = None,
        pattern_message: Optional[str] = None,
        password: bool = False,
        password_strength: str = "medium",
        password_blacklist: Optional[set] = None,
        choices: Optional[List[Any]] = None,
        enum: Optional[Type[Enum]] = None,
        default: Any = _MISSING,
        default_factory: Optional[Callable[[], Any]] = None,
    ):
        self.field_type: Type = type(None)  # Set by metaclass from annotation
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
        if default is not _MISSING and default_factory is not None:
            raise ValueError("Cannot specify both 'default' and 'default_factory'")

    def has_default(self) -> bool:
        """Check if field has a default value"""
        return self.default is not _MISSING or self.default_factory is not None

    def get_default(self) -> Any:
        """Get the default value for this field"""
        if self.default_factory is not None:
            return self.default_factory()
        if self.default is not _MISSING:
            return self.default
        raise ValueError("No default value available")


@dataclass_transform(kw_only_default=True, field_specifiers=(Field,))
class ValidatorMeta(type):
    """Metaclass to collect field definitions"""

    def __new__(mcs, name, bases, attrs):
        fields: Dict[str, FieldInfo] = {}
        annotations = attrs.get("__annotations__", {})

        # Inherit fields from parent classes
        for base in bases:
            if hasattr(base, "_fields"):
                fields.update(base._fields)

        for field_name, field_type in annotations.items():
            if field_name.startswith("_"):
                continue

            # Check if there's a FieldInfo instance defined
            field_def = attrs.get(field_name)
            if isinstance(field_def, FieldInfo):
                # Set field_type from annotation
                field_def.field_type = field_type

                fields[field_name] = field_def
                # Remove the FieldInfo instance from class attributes
                del attrs[field_name]
            else:
                # Create default FieldInfo from annotation
                new_field = FieldInfo(required=True)
                new_field.field_type = field_type
                fields[field_name] = new_field

        attrs["_fields"] = fields
        return super().__new__(mcs, name, bases, attrs)


class BaseValidator(metaclass=ValidatorMeta):
    """Base validator class with security features - powered by Rust"""

    _fields: Dict[str, FieldInfo] = {}

    def __init__(self, **data: Any) -> None:
        self._data: Dict[str, Any] = {}
        self._validate(data)

    def _validate(self, data: Dict[str, Any]) -> None:
        """Validate input data against field definitions"""
        errors: List[Dict[str, Any]] = []

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
                    errors.append(
                        {
                            "loc": ("body", field_name),
                            "type": "missing",
                            "msg": "Field required",
                        }
                    )
                continue

            # Type validation
            try:
                validated_value = self._validate_type(
                    value, field_def.field_type, field_name, field_def
                )
            except ValueError as e:
                errors.append(
                    {
                        "loc": ("body", field_name),
                        "type": "type_error",
                        "msg": str(e),
                    }
                )
                continue

            # String-specific validations (using Rust functions)
            if isinstance(validated_value, str):
                try:
                    if field_def.password:
                        validated_value = PasswordValidator.validate(
                            validated_value,
                            field_def.password_strength,
                            field_def.max_length or 128,
                            field_def.password_blacklist,
                        )
                    elif field_def.email:
                        validated_value = EmailValidator.validate(
                            validated_value,
                            field_def.allow_disposable_email,
                            field_def.max_length or 254,
                        )
                    else:
                        # Sanitization (using Rust)
                        if field_def.sanitize:
                            validated_value = StringSanitizer.sanitize(
                                validated_value, field_def.strict_sanitize
                            )

                        # Pattern validation
                        if field_def.pattern is not None:
                            if not field_def.pattern.match(validated_value):
                                raise ValueError(field_def.pattern_message)

                        # Length validation
                        if (
                            field_def.max_length is not None
                            and len(validated_value) > field_def.max_length
                        ):
                            raise ValueError(
                                f"String length must be at most {field_def.max_length}"
                            )

                        # No empty validation
                        if field_def.no_empty and not validated_value.strip():
                            raise ValueError("String cannot be empty")

                except ValueError as e:
                    errors.append(
                        {
                            "loc": ("body", field_name),
                            "type": "value_error",
                            "msg": str(e),
                        }
                    )
                    continue

            # Choices validation
            if field_def.choices is not None:
                if validated_value not in field_def.choices:
                    choices_str = ", ".join(repr(c) for c in field_def.choices)
                    errors.append(
                        {
                            "loc": ("body", field_name),
                            "type": "value_error",
                            "msg": f"Value must be one of: {choices_str}",
                        }
                    )
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
                        errors.append(
                            {
                                "loc": ("body", field_name),
                                "type": "value_error",
                                "msg": f"Invalid enum value. Valid values: {valid_values}, Valid names: {valid_names}",
                            }
                        )
                        continue

            # Numeric range validation
            if isinstance(validated_value, (int, float)) and not isinstance(
                validated_value, bool
            ):
                try:
                    if (
                        field_def.min_value is not None
                        and validated_value < field_def.min_value
                    ):
                        raise ValueError(
                            f"Value must be at least {field_def.min_value}"
                        )
                    if (
                        field_def.max_value is not None
                        and validated_value > field_def.max_value
                    ):
                        raise ValueError(f"Value must be at most {field_def.max_value}")
                except ValueError as e:
                    errors.append(
                        {
                            "loc": ("body", field_name),
                            "type": "value_error",
                            "msg": str(e),
                        }
                    )
                    continue

            self._data[field_name] = validated_value

        # Check for extra fields
        for key in data:
            if key not in self._fields:
                errors.append(
                    {
                        "loc": ("body", key),
                        "type": "extra_forbidden",
                        "msg": "Extra inputs are not permitted",
                    }
                )

        if errors:
            raise ValidationError(errors)

    def _validate_type(
        self, value: Any, expected_type: Type, field_name: str, field_def: Optional[FieldInfo] = None
    ) -> Any:
        """Validate and convert value to expected type"""
        origin = get_origin(expected_type)

        # Handle Union types (including Optional)
        if origin is Union:
            args = get_args(expected_type)

            # Filter out NoneType
            non_none_types = [t for t in args if t is not type(None)]

            if value is None and type(None) in args:
                return None

            # Check if any type in the union is a BaseValidator subclass
            validator_types = [
                t for t in non_none_types
                if isinstance(t, type) and issubclass(t, BaseValidator)
            ]

            # If we have a validator type and value is a dict, prioritize the validator
            # Don't fall back to plain dict if validator fails - that's just for type hints
            if validator_types and isinstance(value, dict):
                # Try the validator(s) first and don't fall back to dict
                for vtype in validator_types:
                    try:
                        return self._validate_type(value, vtype, field_name, field_def)
                    except (ValueError, ValidationError):
                        continue
                # If all validators failed, re-raise with the first validator to get proper error
                return self._validate_type(value, validator_types[0], field_name, field_def)

            # For non-dict values or unions without validators, try each type
            errors_seen = []
            for union_type in non_none_types:
                try:
                    return self._validate_type(value, union_type, field_name, field_def)
                except (ValueError, ValidationError) as e:
                    errors_seen.append(str(e))
                    continue

            # If we get here, none of the types matched
            if errors_seen:
                raise ValueError(errors_seen[0])  # Return first error
            raise ValueError(f"Value does not match any type in union")

        # Handle List types
        if origin is list:
            if not isinstance(value, list):
                raise ValueError(f"Expected list, got {type(value).__name__}")
            item_type = get_args(expected_type)[0] if get_args(expected_type) else Any
            return [
                self._validate_type(item, item_type, f"{field_name}[{i}]", field_def)  # pyright: ignore[reportArgumentType]
                for i, item in enumerate(value)
            ]

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
            if isinstance(value, expected_type):
                # Already a validator instance
                return value
            if not isinstance(value, dict):
                raise ValueError(
                    f"Expected object/dict for nested validator, got {type(value).__name__}"
                )
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
        result: Dict[str, Any] = {}
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
        if name.startswith("_"):
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}'"
            )
        if name in self._data:
            return self._data[name]
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )
