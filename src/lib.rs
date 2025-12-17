//! SecVal - A high-performance, security-focused validation library
//! 
//! This module provides Rust-powered validation for Python applications,
//! offering XSS prevention, SQL injection protection, email validation,
//! password strength checking, and more.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyTypeError};
use pyo3::types::{PyDict, PyList, PyString, PyBool, PyFloat, PyInt};
use regex::Regex;
use lazy_static::lazy_static;
use std::collections::HashSet;

// ============================================================================
// Lazy Static Regex Patterns
// ============================================================================

lazy_static! {
    // XSS Detection Patterns
    static ref HTML_TAG_PATTERN: Regex = Regex::new(r"(?i)<[^>]*>").unwrap();
    static ref SCRIPT_PATTERN: Regex = Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap();
    static ref EVENT_HANDLER_PATTERN: Regex = Regex::new(r"(?i)\bon\w+\s*=").unwrap();
    static ref JAVASCRIPT_PROTOCOL: Regex = Regex::new(r"(?i)javascript:").unwrap();
    static ref DATA_PROTOCOL: Regex = Regex::new(r"(?i)data:").unwrap();
    static ref VBSCRIPT_PROTOCOL: Regex = Regex::new(r"(?i)vbscript:").unwrap();

    // SQL Injection Patterns
    static ref SQL_KEYWORDS: Regex = Regex::new(
        r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE|CAST|CONVERT)\b"
    ).unwrap();
    static ref SQL_COMMENT: Regex = Regex::new(r"(--|#|/\*|\*/)").unwrap();

    // Path Traversal Pattern
    static ref PATH_TRAVERSAL: Regex = Regex::new(r"\.\.[/\\]").unwrap();

    // Null Byte Pattern
    static ref NULL_BYTE: Regex = Regex::new(r"\x00").unwrap();

    // Email Pattern (RFC 5322 simplified)
    static ref EMAIL_PATTERN: Regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    // Password Patterns
    static ref UPPERCASE_PATTERN: Regex = Regex::new(r"[A-Z]").unwrap();
    static ref LOWERCASE_PATTERN: Regex = Regex::new(r"[a-z]").unwrap();
    static ref DIGIT_PATTERN: Regex = Regex::new(r"\d").unwrap();
    static ref SPECIAL_PATTERN: Regex = Regex::new(r#"[!@#$%^&*()_+\-=\[\]{}|;:'",.<>?/\\`~]"#).unwrap();

    // Disposable Email Domains
    static ref DISPOSABLE_DOMAINS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("tempmail.com");
        set.insert("throwaway.email");
        set.insert("10minutemail.com");
        set.insert("guerrillamail.com");
        set.insert("mailinator.com");
        set.insert("maildrop.cc");
        set.insert("temp-mail.org");
        set.insert("yopmail.com");
        set.insert("fakeinbox.com");
        set.insert("trashmail.com");
        set
    };

    // Common Passwords
    static ref COMMON_PASSWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        for pwd in &[
            "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
            "111111", "2000", "jordan", "superman", "harley", "password1", "password123",
            "letmein", "welcome", "admin", "login", "princess", "admin123", "root",
            "toor", "pass", "test", "guest", "passw0rd", "p@ssw0rd", "p@ssword",
            "123456789", "12345", "1234567", "1234567890", "iloveyou", "sunshine",
        ] {
            set.insert(*pwd);
        }
        set
    };
}

// ============================================================================
// StringSanitizer
// ============================================================================

/// High-performance string sanitizer for preventing injection attacks
#[pyclass]
pub struct StringSanitizer;

#[pymethods]
impl StringSanitizer {
    /// Sanitize a string to prevent injection attacks
    /// 
    /// Args:
    ///     value: String to sanitize
    ///     strict: If True, reject strings with malicious patterns.
    ///            If False, attempt to clean them.
    /// 
    /// Returns:
    ///     Sanitized string
    /// 
    /// Raises:
    ///     ValueError: If strict=True and malicious content detected
    #[staticmethod]
    #[pyo3(signature = (value, strict=true))]
    fn sanitize(value: &str, strict: bool) -> PyResult<String> {
        let mut result = value.to_string();

        // Check for null bytes
        if NULL_BYTE.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("Null bytes are not allowed"));
            }
            result = NULL_BYTE.replace_all(&result, "").to_string();
        }

        // Check for path traversal
        if PATH_TRAVERSAL.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("Path traversal patterns are not allowed"));
            }
            result = PATH_TRAVERSAL.replace_all(&result, "").to_string();
        }

        // Check for script tags
        if SCRIPT_PATTERN.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("Script tags are not allowed"));
            }
            result = SCRIPT_PATTERN.replace_all(&result, "").to_string();
        }

        // Check for HTML tags
        if HTML_TAG_PATTERN.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("HTML tags are not allowed"));
            }
            result = HTML_TAG_PATTERN.replace_all(&result, "").to_string();
        }

        // Check for event handlers
        if EVENT_HANDLER_PATTERN.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("JavaScript event handlers are not allowed"));
            }
            result = EVENT_HANDLER_PATTERN.replace_all(&result, "").to_string();
        }

        // Check for dangerous protocols
        if JAVASCRIPT_PROTOCOL.is_match(&result) || DATA_PROTOCOL.is_match(&result) || VBSCRIPT_PROTOCOL.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("Dangerous URL protocols are not allowed"));
            }
            result = JAVASCRIPT_PROTOCOL.replace_all(&result, "").to_string();
            result = DATA_PROTOCOL.replace_all(&result, "").to_string();
            result = VBSCRIPT_PROTOCOL.replace_all(&result, "").to_string();
        }

        // Check for SQL injection patterns
        if SQL_KEYWORDS.is_match(&result) || SQL_COMMENT.is_match(&result) {
            if strict {
                return Err(PyValueError::new_err("Potential SQL injection pattern detected"));
            }
        }

        // HTML escape special characters
        result = html_escape::encode_text(&result).to_string();

        Ok(result)
    }

    /// Check if a string is safe without modifying it
    #[staticmethod]
    fn is_safe(value: &str) -> bool {
        StringSanitizer::sanitize(value, true).is_ok()
    }
}

// ============================================================================
// EmailValidator
// ============================================================================

/// High-performance email validator
#[pyclass]
pub struct EmailValidator;

#[pymethods]
impl EmailValidator {
    /// Validate an email address
    /// 
    /// Args:
    ///     email: Email address to validate
    ///     allow_disposable: Whether to allow disposable email addresses
    ///     max_length: Maximum email length (RFC 5321 limit is 254)
    /// 
    /// Returns:
    ///     Normalized email address (lowercase)
    /// 
    /// Raises:
    ///     ValueError: If email is invalid
    #[staticmethod]
    #[pyo3(signature = (email, allow_disposable=true, max_length=254))]
    fn validate(email: &str, allow_disposable: bool, max_length: usize) -> PyResult<String> {
        let email = email.trim().to_lowercase();

        // Check length
        if email.len() > max_length {
            return Err(PyValueError::new_err(format!(
                "Email address is too long (max {} characters)", max_length
            )));
        }

        if email.is_empty() {
            return Err(PyValueError::new_err("Email address cannot be empty"));
        }

        // Check basic format
        if !EMAIL_PATTERN.is_match(&email) {
            return Err(PyValueError::new_err("Invalid email address format"));
        }

        // Split into local and domain parts
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(PyValueError::new_err("Invalid email address format"));
        }
        let domain = parts[0];
        let local = parts[1];

        // Validate local part
        if local.is_empty() || local.len() > 64 {
            return Err(PyValueError::new_err("Email local part must be between 1 and 64 characters"));
        }

        // Check for consecutive dots
        if local.contains("..") || domain.contains("..") {
            return Err(PyValueError::new_err("Email address cannot contain consecutive dots"));
        }

        // Local part cannot start or end with a dot
        if local.starts_with('.') || local.ends_with('.') {
            return Err(PyValueError::new_err("Email local part cannot start or end with a dot"));
        }

        // Validate domain part
        if domain.is_empty() || domain.len() > 253 {
            return Err(PyValueError::new_err("Email domain must be between 1 and 253 characters"));
        }

        // Domain must have at least one dot
        if !domain.contains('.') {
            return Err(PyValueError::new_err("Email domain must contain at least one dot"));
        }

        // Check each domain label
        let labels: Vec<&str> = domain.split('.').collect();
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(PyValueError::new_err("Each domain label must be between 1 and 63 characters"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(PyValueError::new_err("Domain labels cannot start or end with a hyphen"));
            }
        }

        // Check TLD is at least 2 characters
        if let Some(tld) = labels.last() {
            if tld.len() < 2 {
                return Err(PyValueError::new_err("Top-level domain must be at least 2 characters"));
            }
        }

        // Check for disposable domains
        if !allow_disposable && DISPOSABLE_DOMAINS.contains(domain) {
            return Err(PyValueError::new_err("Disposable email addresses are not allowed"));
        }

        Ok(email)
    }

    /// Check if an email is valid without raising an exception
    #[staticmethod]
    #[pyo3(signature = (email, allow_disposable=true))]
    fn is_valid(email: &str, allow_disposable: bool) -> bool {
        EmailValidator::validate(email, allow_disposable, 254).is_ok()
    }
}

// ============================================================================
// PasswordValidator
// ============================================================================

/// High-performance password strength validator
#[pyclass]
pub struct PasswordValidator;

#[pymethods]
impl PasswordValidator {
    /// Validate password strength
    /// 
    /// Args:
    ///     password: Password to validate
    ///     min_strength: Minimum strength level ('weak', 'medium', 'strong')
    ///     max_length: Maximum password length
    ///     custom_blacklist: Additional passwords to reject (optional)
    /// 
    /// Returns:
    ///     The validated password
    /// 
    /// Raises:
    ///     ValueError: If password doesn't meet requirements
    #[staticmethod]
    #[pyo3(signature = (password, min_strength="medium", max_length=128, custom_blacklist=None))]
    fn validate(
        password: &str,
        min_strength: &str,
        max_length: usize,
        custom_blacklist: Option<Vec<String>>,
    ) -> PyResult<String> {
        let (min_len, require_upper, require_lower, require_digit, require_special, check_common) = 
            match min_strength {
                "weak" => (6, false, false, false, false, false),
                "medium" => (8, true, true, true, false, true),
                "strong" => (12, true, true, true, true, true),
                _ => return Err(PyValueError::new_err(
                    "Invalid strength level. Must be one of: 'weak', 'medium', 'strong'"
                )),
            };

        // Check length
        if password.len() < min_len {
            return Err(PyValueError::new_err(format!(
                "Password must be at least {} characters long", min_len
            )));
        }

        if password.len() > max_length {
            return Err(PyValueError::new_err(format!(
                "Password must be at most {} characters long", max_length
            )));
        }

        // Check for uppercase
        if require_upper && !UPPERCASE_PATTERN.is_match(password) {
            return Err(PyValueError::new_err("Password must contain at least one uppercase letter"));
        }

        // Check for lowercase
        if require_lower && !LOWERCASE_PATTERN.is_match(password) {
            return Err(PyValueError::new_err("Password must contain at least one lowercase letter"));
        }

        // Check for digit
        if require_digit && !DIGIT_PATTERN.is_match(password) {
            return Err(PyValueError::new_err("Password must contain at least one digit"));
        }

        // Check for special character
        if require_special && !SPECIAL_PATTERN.is_match(password) {
            return Err(PyValueError::new_err("Password must contain at least one special character"));
        }

        // Check against common passwords
        if check_common {
            let password_lower = password.to_lowercase();
            if COMMON_PASSWORDS.contains(password_lower.as_str()) {
                return Err(PyValueError::new_err("Password is too common. Please choose a stronger password"));
            }

            // Check custom blacklist
            if let Some(blacklist) = custom_blacklist {
                let blacklist_lower: HashSet<String> = blacklist.iter()
                    .map(|s| s.to_lowercase())
                    .collect();
                if blacklist_lower.contains(&password_lower) {
                    return Err(PyValueError::new_err("Password is not allowed"));
                }
            }
        }

        Ok(password.to_string())
    }

    /// Check if a password is valid without raising an exception
    #[staticmethod]
    #[pyo3(signature = (password, min_strength="medium"))]
    fn is_valid(password: &str, min_strength: &str) -> bool {
        PasswordValidator::validate(password, min_strength, 128, None).is_ok()
    }

    /// Determine the strength level of a password
    /// 
    /// Returns:
    ///     'strong', 'medium', 'weak', or 'invalid'
    #[staticmethod]
    fn get_strength(password: &str) -> String {
        for strength in &["strong", "medium", "weak"] {
            if PasswordValidator::is_valid(password, strength) {
                return strength.to_string();
            }
        }
        "invalid".to_string()
    }
}

// ============================================================================
// ValidationError
// ============================================================================

/// Custom validation error that can hold multiple errors
#[pyclass]
#[derive(Clone)]
pub struct ValidationError {
    errors_list: Vec<PyObject>,
}

#[pymethods]
impl ValidationError {
    #[new]
    fn new(errors: Vec<PyObject>) -> Self {
        ValidationError { errors_list: errors }
    }

    /// Get the list of validation errors
    fn errors(&self, py: Python) -> Vec<PyObject> {
        self.errors_list.clone()
    }

    fn __str__(&self) -> String {
        format!("ValidationError: {} error(s)", self.errors_list.len())
    }

    fn __repr__(&self) -> String {
        format!("ValidationError(errors={})", self.errors_list.len())
    }
}

// ============================================================================
// Field Descriptor
// ============================================================================

/// Field descriptor for validation rules
#[pyclass]
#[derive(Clone)]
pub struct Field {
    #[pyo3(get)]
    pub field_type: PyObject,
    #[pyo3(get)]
    pub required: bool,
    #[pyo3(get)]
    pub no_empty: bool,
    #[pyo3(get)]
    pub min_value: Option<f64>,
    #[pyo3(get)]
    pub max_value: Option<f64>,
    #[pyo3(get)]
    pub sanitize: bool,
    #[pyo3(get)]
    pub strict_sanitize: bool,
    #[pyo3(get)]
    pub max_length: Option<usize>,
    #[pyo3(get)]
    pub email: bool,
    #[pyo3(get)]
    pub allow_disposable_email: bool,
    #[pyo3(get)]
    pub pattern: Option<String>,
    #[pyo3(get)]
    pub pattern_message: String,
    #[pyo3(get)]
    pub password: bool,
    #[pyo3(get)]
    pub password_strength: String,
    #[pyo3(get)]
    pub password_blacklist: Option<Vec<String>>,
    #[pyo3(get)]
    pub choices: Option<PyObject>,
    #[pyo3(get)]
    pub enum_type: Option<PyObject>,
    #[pyo3(get)]
    pub default: Option<PyObject>,
    #[pyo3(get)]
    pub default_factory: Option<PyObject>,
    
    // Compiled regex (not exposed to Python)
    compiled_pattern: Option<Regex>,
}

#[pymethods]
impl Field {
    #[new]
    #[pyo3(signature = (
        field_type,
        required=true,
        no_empty=false,
        min_value=None,
        max_value=None,
        sanitize=true,
        strict_sanitize=true,
        max_length=None,
        email=false,
        allow_disposable_email=true,
        pattern=None,
        pattern_message=None,
        password=false,
        password_strength="medium",
        password_blacklist=None,
        choices=None,
        enum_type=None,
        default=None,
        default_factory=None
    ))]
    fn new(
        field_type: PyObject,
        required: bool,
        no_empty: bool,
        min_value: Option<f64>,
        max_value: Option<f64>,
        sanitize: bool,
        strict_sanitize: bool,
        max_length: Option<usize>,
        email: bool,
        allow_disposable_email: bool,
        pattern: Option<String>,
        pattern_message: Option<String>,
        password: bool,
        password_strength: &str,
        password_blacklist: Option<Vec<String>>,
        choices: Option<PyObject>,
        enum_type: Option<PyObject>,
        default: Option<PyObject>,
        default_factory: Option<PyObject>,
    ) -> PyResult<Self> {
        // Validate that both default and default_factory are not set
        if default.is_some() && default_factory.is_some() {
            return Err(PyValueError::new_err("Cannot specify both 'default' and 'default_factory'"));
        }

        // Compile regex pattern if provided
        let compiled_pattern = if let Some(ref p) = pattern {
            Some(Regex::new(p).map_err(|e| PyValueError::new_err(format!("Invalid regex pattern: {}", e)))?)
        } else {
            None
        };

        Ok(Field {
            field_type,
            required,
            no_empty,
            min_value,
            max_value,
            sanitize,
            strict_sanitize,
            max_length,
            email,
            allow_disposable_email,
            pattern,
            pattern_message: pattern_message.unwrap_or_else(|| "Value does not match required pattern".to_string()),
            password,
            password_strength: password_strength.to_string(),
            password_blacklist,
            choices,
            enum_type,
            default,
            default_factory,
            compiled_pattern,
        })
    }

    /// Check if field has a default value
    fn has_default(&self) -> bool {
        self.default.is_some() || self.default_factory.is_some()
    }

    /// Get the default value for this field
    fn get_default(&self, py: Python) -> PyResult<PyObject> {
        if let Some(ref factory) = self.default_factory {
            // Call the factory function
            factory.call0(py)
        } else if let Some(ref default) = self.default {
            Ok(default.clone_ref(py))
        } else {
            Err(PyValueError::new_err("No default value available"))
        }
    }
}

impl Field {
    /// Validate a string against the compiled pattern (internal use)
    pub fn matches_pattern(&self, value: &str) -> bool {
        if let Some(ref pattern) = self.compiled_pattern {
            pattern.is_match(value)
        } else {
            true
        }
    }
}

// ============================================================================
// Core Validation Functions
// ============================================================================

/// Validate a string value with all applicable rules
#[pyfunction]
#[pyo3(signature = (value, field, field_name))]
fn validate_string(py: Python, value: &str, field: &Field, field_name: &str) -> PyResult<String> {
    let mut result = value.to_string();

    // Password validation
    if field.password {
        result = PasswordValidator::validate(
            &result,
            &field.password_strength,
            field.max_length.unwrap_or(128),
            field.password_blacklist.clone(),
        )?;
        return Ok(result);
    }

    // Email validation
    if field.email {
        result = EmailValidator::validate(
            &result,
            field.allow_disposable_email,
            field.max_length.unwrap_or(254),
        )?;
        return Ok(result);
    }

    // Sanitization (for non-email, non-password fields)
    if field.sanitize {
        result = StringSanitizer::sanitize(&result, field.strict_sanitize)?;
    }

    // Pattern validation
    if !field.matches_pattern(&result) {
        return Err(PyValueError::new_err(&field.pattern_message));
    }

    // Length validation
    if let Some(max_len) = field.max_length {
        if result.len() > max_len {
            return Err(PyValueError::new_err(format!(
                "String length must be at most {}", max_len
            )));
        }
    }

    // No empty validation
    if field.no_empty && result.trim().is_empty() {
        return Err(PyValueError::new_err("String cannot be empty"));
    }

    Ok(result)
}

/// Validate a numeric value
#[pyfunction]
fn validate_number(value: f64, field: &Field, field_name: &str) -> PyResult<f64> {
    if let Some(min_val) = field.min_value {
        if value < min_val {
            return Err(PyValueError::new_err(format!(
                "Value must be at least {}", min_val
            )));
        }
    }

    if let Some(max_val) = field.max_value {
        if value > max_val {
            return Err(PyValueError::new_err(format!(
                "Value must be at most {}", max_val
            )));
        }
    }

    Ok(value)
}

/// Check if a value is in the allowed choices
#[pyfunction]
fn validate_choices(py: Python, value: PyObject, choices: &PyObject, field_name: &str) -> PyResult<bool> {
    let choices_list = choices.downcast_bound::<PyList>(py)?;
    
    for choice in choices_list.iter() {
        if value.bind(py).eq(&choice)? {
            return Ok(true);
        }
    }
    
    let choices_repr: Vec<String> = choices_list
        .iter()
        .map(|c| c.repr().map(|r| r.to_string()).unwrap_or_default())
        .collect();
    
    Err(PyValueError::new_err(format!(
        "Value must be one of: {}", choices_repr.join(", ")
    )))
}

// ============================================================================
// Python Module
// ============================================================================

/// SecVal - High-performance validation library written in Rust
#[pymodule]
fn _secval(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<StringSanitizer>()?;
    m.add_class::<EmailValidator>()?;
    m.add_class::<PasswordValidator>()?;
    m.add_class::<ValidationError>()?;
    m.add_class::<Field>()?;
    m.add_function(wrap_pyfunction!(validate_string, m)?)?;
    m.add_function(wrap_pyfunction!(validate_number, m)?)?;
    m.add_function(wrap_pyfunction!(validate_choices, m)?)?;
    Ok(())
}
