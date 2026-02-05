# src/utils/csv_sanitizer.py
"""
Utility functions for sanitizing text output to be CSV-safe.
Prevents issues with newlines, quotes, and special characters in CSV files.
"""


def sanitize_for_csv(text: str, max_length: int = 500, join_char: str = '; ') -> str:
    """
    Sanitize text for safe CSV output.

    Args:
        text: Input text that may contain newlines, quotes, etc.
        max_length: Maximum length of output (default: 500)
        join_char: Character to use when joining multiple lines (default: '; ')

    Returns:
        Sanitized text safe for CSV output
    """
    if not text:
        return ""

    # Replace newlines with join character
    sanitized = text.replace('\n', join_char).replace('\r', '')

    # Clean up whitespace
    sanitized = ' '.join(sanitized.split())

    # Remove duplicate join characters
    if join_char:
        double_join = join_char + join_char
        while double_join in sanitized:
            sanitized = sanitized.replace(double_join, join_char)

    # Strip leading/trailing join characters
    sanitized = sanitized.strip(join_char.strip())

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


def sanitize_error_message(error: Exception, max_length: int = 200) -> str:
    """
    Sanitize exception messages for CSV output.
    Removes newlines and stack traces, keeping only the main error message.

    Args:
        error: Exception object
        max_length: Maximum length of error message (default: 200)

    Returns:
        Clean error message safe for CSV
    """
    error_msg = str(error)

    # Remove newlines and carriage returns
    error_msg = error_msg.replace('\n', ' ').replace('\r', ' ')

    # Clean up whitespace
    error_msg = ' '.join(error_msg.split())

    # Truncate if too long
    if len(error_msg) > max_length:
        error_msg = error_msg[:max_length] + "..."

    return error_msg
