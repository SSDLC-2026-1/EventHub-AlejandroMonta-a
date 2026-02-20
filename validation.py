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


CARD_DIGITS_RE = re.compile(r"")     # digits only
CVV_RE = re.compile(r"")             # 3 or 4 digits
EXP_RE = re.compile(r"")             # MM/YY format
EMAIL_BASIC_RE = re.compile(r"")     # basic email structure
NAME_ALLOWED_RE = re.compile(r"")    # allowed name characters


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
