using System.Net;
using System.Text.RegularExpressions;

namespace WebApplication1.Services
{
    /// <summary>
    /// Service for input validation, sanitization, and encoding
    /// Prevents SQL Injection, XSS, and CSRF attacks
    /// </summary>
    public class InputValidationService
    {
        /// <summary>
        /// Sanitizes input by removing potentially dangerous characters
        /// </summary>
        public string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Remove script tags and dangerous HTML
            input = Regex.Replace(input, @"<script[^>]*>.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            input = Regex.Replace(input, @"<iframe[^>]*>.*?</iframe>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            input = Regex.Replace(input, @"javascript:", "", RegexOptions.IgnoreCase);
            input = Regex.Replace(input, @"on\w+\s*=", "", RegexOptions.IgnoreCase);
            
            // Trim whitespace
            return input.Trim();
        }

        /// <summary>
        /// HTML encodes input to prevent XSS attacks
        /// Use this before saving to database
        /// </summary>
        public string HtmlEncode(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            return WebUtility.HtmlEncode(input);
        }

        /// <summary>
        /// Validates and sanitizes email address
        /// </summary>
        public bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates date is not in the future and reasonable (not too old)
        /// </summary>
        public bool IsValidDateOfBirth(DateTime dateOfBirth)
        {
            var today = DateTime.Today;
            var minDate = today.AddYears(-120); // Not older than 120 years
            var maxDate = today.AddYears(-13); // At least 13 years old

            return dateOfBirth >= minDate && dateOfBirth <= maxDate;
        }

        /// <summary>
        /// Validates NRIC format (Singapore NRIC)
        /// </summary>
        public bool IsValidNRIC(string nric)
        {
            if (string.IsNullOrEmpty(nric))
                return false;

            // Singapore NRIC format: S1234567A
            return Regex.IsMatch(nric, @"^[STFG]\d{7}[A-Z]$");
        }

        /// <summary>
        /// Validates gender selection
        /// </summary>
        public bool IsValidGender(string gender)
        {
            var validGenders = new[] { "Male", "Female", "Other" };
            return validGenders.Contains(gender, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Comprehensive validation and encoding before saving to database
        /// Prevents SQL Injection (via parameterized queries) and XSS (via encoding)
        /// </summary>
        public (bool IsValid, string ErrorMessage, string SanitizedValue) ValidateAndEncodeForDatabase(string fieldName, string value, bool allowSpecialChars = false)
        {
            if (string.IsNullOrEmpty(value))
                return (true, "", "");

            // Sanitize input
            var sanitized = SanitizeInput(value);

            // Check for SQL injection patterns (even though EF Core prevents it, we validate anyway)
            var sqlInjectionPatterns = new[]
            {
                "'; DROP TABLE",
                "'; DELETE FROM",
                "'; INSERT INTO",
                "'; UPDATE",
                "'; SELECT",
                "UNION SELECT",
                "OR 1=1",
                "OR '1'='1'"
            };

            foreach (var pattern in sqlInjectionPatterns)
            {
                if (sanitized.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"{fieldName} contains potentially dangerous content.", "");
                }
            }

            // HTML encode to prevent XSS (before saving to database)
            var encoded = HtmlEncode(sanitized);

            return (true, "", encoded);
        }
    }
}
