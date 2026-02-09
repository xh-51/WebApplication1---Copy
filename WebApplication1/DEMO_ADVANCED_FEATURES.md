# Advanced Features - Quick Demo Guide

## What Was Implemented ✅

1. **Account Policies & Recovery** (10%)
   - Automatic lockout recovery (5 minutes)
   - Password history (max 2)
   - Change password
   - Reset password (email link)
   - Minimum password age (5 minutes)
   - Maximum password age (90 days)

2. **Two-Factor Authentication (2FA)**
   - QR code setup
   - TOTP verification
   - Integrated login flow

## Quick Demonstration (7-8 minutes)

### 1. Automatic Lockout Recovery (30 seconds)
**Show**: `Program.cs` line 66
```csharp
options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Auto-recovery
```

**Explain**: "Account automatically unlocks after 5 minutes - no manual intervention needed."

**Test**: 
- Try 3 wrong passwords → Account locked
- Wait 5 minutes → Try login again → Works!

---

### 2. Password History (1 minute)
**Show**: `PasswordPolicyService.cs` - `CanUsePassword()` method
**Show**: `appsettings.json` - `"MaxHistory": 2`

**Explain**: "Prevents reusing the last 2 passwords for security."

**Test**:
- Change password to "NewPass123!@#"
- Try to change it again to "NewPass123!@#" → Error: "Cannot reuse password"

---

### 3. Change Password (1 minute)
**Navigate**: `/Account/ChangePassword` (or click "Change Password" on homepage)

**Show**:
- Current password field
- New password field (with validation)
- Password policy notice

**Test**:
- Enter current password
- Enter new password
- Submit → Success!

**Show Code**: `AccountController.ChangePassword()` - Shows validation logic

---

### 4. Reset Password (1 minute)
**Navigate**: `/Account/ForgotPassword` (or "Forgot password?" link on login)

**Show**:
- Email input form
- Submit → Shows reset link (in demo)
- Click link → Reset password form

**Test**:
- Enter email
- Submit → See reset link
- Click link → Enter new password → Success!

**Explain**: "In production, the link would be sent via email. For demo, we show it here."

---

### 5. Minimum Password Age (30 seconds)
**Show**: `PasswordPolicyService.cs` - `CanChangePassword()` method
**Show**: `appsettings.json` - `"MinAgeMinutes": 5`

**Test**:
- Change password
- Immediately try to change again → Error: "Cannot change within 5 minutes"

---

### 6. Maximum Password Age (30 seconds)
**Show**: `PasswordPolicyService.cs` - `MustChangePassword()` method
**Show**: `appsettings.json` - `"MaxAgeMinutes": 129600` (90 days)

**Explain**: 
- "Password expires after 90 days"
- "Shows warning 7 days before expiry"
- "Forces change if expired"

**Show Code**: `AccountController.Login()` line 277 - Checks on login

---

### 7. Two-Factor Authentication (2 minutes)

#### Setup:
**Navigate**: `/Account/Enable2FA` (or "Enable 2FA" on homepage)

**Show**:
- QR code (for scanning with authenticator app)
- Manual key entry option
- Verification form

**Test**:
1. Scan QR code with Google Authenticator/Microsoft Authenticator
2. Enter 6-digit code from app
3. Submit → 2FA enabled!

#### Login with 2FA:
**Test**:
1. Logout
2. Login with email/password
3. **Shows**: 2FA verification page
4. Enter code from authenticator app
5. Submit → Logged in!

**Show Code**: 
- `AccountController.Enable2FA()` - Setup
- `AccountController.Verify2FA()` - Verification
- `AccountController.Login()` - 2FA check

---

## Summary Points to Tell Your Lecturer

### Account Policies:
1. ✅ **Automatic Recovery**: Account unlocks after 5 minutes (no manual intervention)
2. ✅ **Password History**: Prevents reusing last 2 passwords
3. ✅ **Change Password**: Full implementation with all policy checks
4. ✅ **Reset Password**: Secure token-based email link
5. ✅ **Password Age**: 
   - Minimum: 5 minutes between changes
   - Maximum: 90 days before required change
   - Warnings: 7 days before expiry

### Two-Factor Authentication:
1. ✅ **Setup**: QR code + manual key entry
2. ✅ **Verification**: TOTP 6-digit codes
3. ✅ **Integration**: Seamlessly integrated into login flow
4. ✅ **Security**: Uses industry-standard authenticator apps

## Files to Show

1. `Services/PasswordPolicyService.cs` - Password policy logic
2. `Controllers/AccountController.cs` - Password management & 2FA
3. `appsettings.json` - Policy configuration
4. `Program.cs` - Lockout and 2FA configuration

## Test URLs

- `/Account/ChangePassword` - Change password
- `/Account/ForgotPassword` - Request password reset
- `/Account/Enable2FA` - Enable 2FA
- `/Account/Verify2FA` - Verify 2FA code (during login)

## Total Time: ~7-8 minutes
