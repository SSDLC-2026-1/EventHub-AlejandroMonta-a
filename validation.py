"""
payment_validation.py

Skeleton file for input validation exercise.
You must implement each validation function according to the
specification provided in the docstrings.

All validation functions must return:

    (clean_value, error_message)

Where:
    clean_value: normalized/validated value (or empty string if invalid)
    error_message: empty string if valid, otherwise error description
"""

import re
import unicodedata
from datetime import datetime
from typing import Tuple, Dict


# =============================
# Regular Patterns
# =============================


CARD_DIGITS_RE = re.compile(r"^\d+$")                          # digits only
CVV_RE = re.compile(r"^\d{3,4}$")                              # 3 or 4 digits
EXP_RE = re.compile(r"^(0[1-9]|1[0-2])\/(\d{2})$")             # MM/YY format
EMAIL_BASIC_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")     # basic email structure
NAME_ALLOWED_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ'\- ]+$")      # allowed name characters

PHONE_RE = re.compile(r"^\d{7,15}$") 

# =============================
# Utility Functions
# =============================

def normalize_basic(value: str) -> str:
    """
    Normalize input using NFKC and strip whitespace.
    """

    return unicodedata.normalize("NFKC", (value or "")).strip()


def luhn_is_valid(number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Input:
        number (str) -> digits only

    Returns:
        True if valid according to Luhn algorithm
        False otherwise
    """
    if not number or not number.isdigit():
        return False
    
    digits = [int(d) for d in number]
    checksum = 0
    
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    return checksum % 10 == 0

   

# =============================
# Field Validations
# =============================

def validate_card_number(card_number: str) -> Tuple[str, str]:
    """
    Validate credit card number.

    Requirements:
    - Normalize input
    - Remove spaces and hyphens before validation
    - Must contain digits only
    - Length between 13 and 19 digits
    - BONUS: Must pass Luhn algorithm

    Input:
        card_number (str)

    Returns:
        (card, error_message)

    Notes:
        - If invalid → return ("", "Error message")
        - If valid → return (all credit card digits, "")
    """
    card_number = normalize_basic(card_number)
    card_number = re.sub(r"[^0-9]", "", card_number)
    if not luhn_is_valid(card_number):
        return "", "Invalid card number by Luhn"
    if card_number.isdigit() and len(card_number) >= 13 and len(card_number) <= 19:
        return card_number, ""

    else: 
        return "", "Only digits allowed, please retype your card number"

def validate_exp_date(exp_date: str) -> Tuple[str, str]:
    """
    Validate expiration date.

    Requirements:
    - Format must be MM/YY
    - Month must be between 01 and 12
    - Must not be expired compared to current UTC date
    - Optional: limit to reasonable future (e.g., +15 years)

    Input:
        exp_date (str)

    Returns:
        (normalized_exp_date, error_message)
    """
    exp_date = normalize_basic(exp_date)
    try:
        date_obj = datetime.strptime(exp_date, '%m/%y')
    except ValueError:
        return "", "Please use MM/YY format"


    today = datetime.now()

    
    if date_obj.year < today.year or (date_obj.year == today.year and date_obj.month < today.month):
        return "", "Out of date, use another card."
    else:
        return "", ""

def validate_cvv(cvv: str) -> Tuple[str, str]:
    """
    Validate CVV.

    Requirements:
    - Must contain only digits
    - Must be exactly 3 or 4 digits
    - Should NOT return the CVV value for storage

    Input:
        cvv (str)

    Returns:
        ("", error_message)
        (always return empty clean value for security reasons)
    """
    cvv = normalize_basic(cvv)
    if cvv.isdigit() and  len(cvv) in [3, 4]:
        return "", ""
    return "", "Invalid CVV"


def validate_billing_email(billing_email: str) -> Tuple[str, str]:
    """
    Validate billing email.

    Requirements:
    - Normalize (strip + lowercase)
    - Max length 254
    - Must match basic email pattern

    Input:
        billing_email (str)

    Returns:
        (normalized_email, error_message)
    """
    billing_email = normalize_basic(billing_email).lower()
    normalized_email = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if len(billing_email) > 254:
        return "", "Too long"

    if re.match(normalized_email, billing_email):
        return billing_email, ""
    else:
        return "", "Invalid email format"


def validate_name_on_card(name_on_card: str) -> Tuple[str, str]:
    """
    Validate name on card.

    Requirements:
    - Normalize input
    - Collapse multiple spaces
    - Length between 2 and 60 characters
    - Only letters (including accents), spaces, apostrophes, hyphens

    Input:
        name_on_card (str)

    Returns:
        (normalized_name, error_message)
    """
    name_on_card = normalize_basic(name_on_card)
    normalized_name = " ".join(name_on_card.split())
    if (len(normalized_name) < 2 or len(normalized_name) > 60):
        return "", "Name must be have only strings"
    all_digits_allowed = r"^[a-zA-ZÀ-ÿ\u00f1\u00d1\s'-]+$"
    if re.match(all_digits_allowed, normalized_name):
        return normalized_name, ""
    else:
        return "", "Invalid name format."

# =============================
# Laboratory_1 Validations
# =============================

def validate_full_name(name: str) -> Tuple[str, str]:

    name = normalize_basic(name)
    name = re.sub(r"\s+", " ", name)

    if not name:
        return "", "Full name is required"

    if (len(name) < 2 or len(name) > 60):
        return "", "Full name must be between 2 and 60 characters"

    if not NAME_ALLOWED_RE.match(name):
        return "", "Invalid characters in name"

    return name, ""

def validate_email(email: str) -> Tuple[str, str]:

    email = normalize_basic(email).lower()

    if not email:
        return "", "Email is required"

    if (len(email) > 254):
        return "", "Email too long"

    if not EMAIL_BASIC_RE.match(email):
        return "", "Invalid email format"

    return email, ""

def validate_phone(phone: str) -> Tuple[str, str]:

    phone = normalize_basic(phone)
    phone = phone.replace(" ", "")

    if not phone:
        return "", "Phone is required"

    if not PHONE_RE.match(phone):
        return "", "Phone must contain 7 to 15 digits"

    return phone, ""

def validate_password(password: str, email: str) -> Tuple[str, str]:

    password = normalize_basic(password)

    if (len(password) < 8 or len(password) > 64):
        return "", "Password must be between 8 and 64 characters."

    if " " in password:
        return "", "Password cannot contain spaces."

    if password.lower() == email.lower():
        return "", "Password cannot be equal to email."

    if not re.search(r"[A-Z]", password):
        return "", "Must include uppercase letter."

    if not re.search(r"[a-z]", password):
        return "", "Must include lowercase letter."

    if not re.search(r"[0-9]", password):
        return "", "Must include number."

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}<>?]", password):
        return "", "Must include special character."

    return password, ""

def validate_password_confirmation(password: str, confirm: str) -> Tuple[str, str]:

    confirm = normalize_basic(confirm)

    if password != confirm:
        return "", "Passwords do not match"

    return "", ""

# =============================
# Orchestrator Function
# =============================

def validate_payment_form(
    card_number: str,
    exp_date: str,
    cvv: str,
    name_on_card: str,
    billing_email: str
) -> Tuple[Dict, Dict]:
    """
    Orchestrates all field validations.

    Returns:
        clean (dict)  -> sanitized values safe for storage/use
        errors (dict) -> field_name -> error_message
    """

    clean = {}
    errors = {}

    card, err = validate_card_number(card_number)
    if err:
        errors["card_number"] = err
    clean["card"] = card

    exp_clean, err = validate_exp_date(exp_date)
    if err:
        errors["exp_date"] = err
    clean["exp_date"] = exp_clean

    _, err = validate_cvv(cvv)
    if err:
        errors["cvv"] = err

    name_clean, err = validate_name_on_card(name_on_card)
    if err:
        errors["name_on_card"] = err
    clean["name_on_card"] = name_clean

    email_clean, err = validate_billing_email(billing_email)
    if err:
        errors["billing_email"] = err
    clean["billing_email"] = email_clean

    return clean, errors

# =============================
# Laboratory_1 Orchestrator Function
# =============================

def validate_register_form(
    full_name: str,
    email: str,
    phone: str,
    password: str,
    confirm_password: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    name_clean, err = validate_full_name(full_name)
    if err:
        errors["full_name"] = err
    clean["full_name"] = name_clean

    email_clean, err = validate_email(email)
    if err:
        errors["email"] = err
    clean["email"] = email_clean

    phone_clean, err = validate_phone(phone)
    if err:
        errors["phone"] = err
    clean["phone"] = phone_clean

    password_clean, err = validate_password(password, email)
    if err:
        errors["password"] = err
    clean["password"] = password_clean

    _, err = validate_password_confirmation(password, confirm_password)
    if err:
        errors["confirm_password"] = err

    return clean, errors

def validate_profile_form(
    full_name: str,
    phone: str,
    new_password: str,
    confirm_new_password: str,
    user_email: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    name_clean, err = validate_full_name(full_name)
    if err:
        errors["full_name"] = err
    clean["full_name"] = name_clean

    phone_clean, err = validate_phone(phone)
    if err:
        errors["phone"] = err
    clean["phone"] = phone_clean

    if new_password:

        password_clean, err = validate_password(new_password, user_email)
        if err:
            errors["new_password"] = err
        clean["new_password"] = password_clean

        _, err = validate_password_confirmation(new_password, confirm_new_password)
        if err:
            errors["confirm_new_password"] = err

    return clean, errors

def validate_login_form(
    email: str,
    password: str
) -> Tuple[Dict, Dict]:

    clean = {}
    errors = {}

    email_clean, err = validate_email(email)
    if err:
        errors["email"] = "Invalid credentials"
    clean["email"] = email_clean

    password = normalize_basic(password)
    if not password:
        errors["password"] = "Invalid credentials"

    clean["password"] = password

    return clean, errors