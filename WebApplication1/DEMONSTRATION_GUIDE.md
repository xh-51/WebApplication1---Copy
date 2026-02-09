# Input Validation - Demonstration Guide for Lecturer

## Quick Overview

This application implements **comprehensive input validation** to prevent SQL Injection, XSS, and CSRF attacks with both client-side and server-side validation.

## Key Files to Show

1. **`Services/InputValidationService.cs`** - Core validation service
2. **`Controllers/AccountController.cs`** - Lines 45-120 (validation logic)
3. **`Models/RegisterViewModel.cs`** - Validation attributes
4. **`Views/Account/Register.cshtml`** - Client-side validation

## What to Demonstrate

### 1. CSRF Protection (30 seconds)
**Show**: `Register.cshtml` line 15
```html
@Html.AntiForgeryToken() <!-- CSRF Token -->
```

**Show**: `AccountController.cs` line 44
```csharp
[ValidateAntiForgeryToken] // CSRF Protection
```

**Explain**: "Every POST form has an anti-forgery token that prevents CSRF attacks."

---

### 2. XSS Prevention (1 minute)
**Show**: `AccountController.cs` lines 108-119
```csharp
FirstName = _inputValidationService.HtmlEncode(firstNameValidation.SanitizedValue), // HTML encoded
LastName = _inputValidationService.HtmlEncode(lastNameValidation.SanitizedValue), // HTML encoded
```

**Test**: Enter `<script>alert('XSS')</script>` in First Name field
- **Result**: Error message appears
- **If bypassed**: Data is HTML encoded before saving (safe)

**Show**: `InputValidationService.cs` - `SanitizeInput()` method removes script tags

---

### 3. SQL Injection Prevention (1 minute)
**Show**: `AccountController.cs` line 124
```csharp
var result = await _userManager.CreateAsync(user, model.Password);
```

**Explain**: "Entity Framework Core uses parameterized queries automatically - no raw SQL."

**Show**: `InputValidationService.cs` lines 50-60 - SQL injection pattern detection

**Test**: Try entering `'; DROP TABLE Users--` in any field
- **Result**: Error: "contains potentially dangerous content"

---

### 4. Input Validation (2 minutes)

#### Email Validation
**Show**: `RegisterViewModel.cs` line 27
```csharp
[EmailAddress(ErrorMessage = "Invalid email address")]
```

**Show**: `AccountController.cs` line 48
```csharp
if (!_inputValidationService.IsValidEmail(model.Email))
```

**Test**: Enter `invalid-email` → Shows error

#### NRIC Validation
**Show**: `RegisterViewModel.cs` line 23
```csharp
[RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC format")]
```

**Test**: Enter `12345678` → Shows error
**Test**: Enter `S1234567A` → Valid

#### Date Validation
**Show**: `AccountController.cs` line 58
```csharp
if (!_inputValidationService.IsValidDateOfBirth(model.DateOfBirth))
```

**Test**: Enter future date → Shows error
**Test**: Enter date making user < 13 years old → Shows error

---

### 5. Client & Server Validation (1 minute)
**Show**: `Register.cshtml` - Has validation scripts
```html
@section Scripts {
    @{await Html.RenderPartialAsync("_ValidationScriptsPartial");}
}
```

**Show**: `AccountController.cs` - Server-side validation (lines 47-75)

**Explain**: 
- Client-side: Immediate feedback, better UX
- Server-side: Security layer (works even if JavaScript disabled)

---

### 6. Error Messages (30 seconds)
**Show**: `Register.cshtml` line 16
```html
<div asp-validation-summary="All" class="alert alert-danger"></div>
```

**Show**: Field-level errors
```html
<span asp-validation-for="FirstName" class="text-danger"></span>
```

**Test**: Submit empty form → See all error messages

---

### 7. Encoding Before Database Save (1 minute)
**Show**: `AccountController.cs` lines 108-119
- All text fields are HTML encoded before saving
- NRIC is encrypted (additional security)

**Show**: `InputValidationService.cs` - `HtmlEncode()` method

**Explain**: "All user inputs are sanitized, then HTML encoded before saving to prevent XSS attacks."

---

## Summary Points to Mention

1. ✅ **SQL Injection**: Prevented by EF Core parameterized queries + pattern detection
2. ✅ **XSS**: Prevented by HTML encoding + input sanitization
3. ✅ **CSRF**: Prevented by Anti-Forgery tokens on all forms
4. ✅ **Input Validation**: Both client-side (UX) and server-side (security)
5. ✅ **Error Messages**: Clear, user-friendly feedback
6. ✅ **Encoding**: All inputs HTML encoded before database save

## Total Demonstration Time: ~7-8 minutes

## Files to Open in IDE

1. `Services/InputValidationService.cs` - Show validation service
2. `Controllers/AccountController.cs` - Show validation in action
3. `Models/RegisterViewModel.cs` - Show validation attributes
4. `Views/Account/Register.cshtml` - Show client-side validation

## Quick Test Script

1. Open registration form
2. Try entering `<script>alert('XSS')</script>` → See error
3. Try entering `'; DROP TABLE` → See error
4. Try invalid email → See error
5. Try invalid NRIC → See error
6. Submit empty form → See all validation errors
7. Show code: `[ValidateAntiForgeryToken]` → Explain CSRF protection
8. Show code: `HtmlEncode()` → Explain XSS prevention
9. Show code: `CreateAsync()` → Explain SQL injection prevention
