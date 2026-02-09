# Where to Put Your SMTP Keys / Password

SMTP is used for **Forgot Password** emails. If SMTP is not configured, the app still runs but does not send emails (it logs a warning instead).

## 1. **appsettings.json** (or User Secrets / environment for production)

Put your SMTP settings under the **`Smtp`** section:

```json
"Smtp": {
  "Host": "smtp.gmail.com",
  "Port": 587,
  "UserName": "your-email@gmail.com",
  "Password": "your-app-password",
  "FromEmail": "your-email@gmail.com",
  "FromName": "Ace Job Agency",
  "EnableSsl": true
}
```

| Key         | Description |
|------------|-------------|
| **Host**   | SMTP server (e.g. `smtp.gmail.com`, `smtp.office365.com`). If empty, no email is sent. |
| **Port**   | Usually `587` (TLS) or `465` (SSL). |
| **UserName** | SMTP login (often your email). |
| **Password** | SMTP password or **App Password** (for Gmail/Google, use an App Password, not your normal password). |
| **FromEmail** | Sender address (often same as UserName). |
| **FromName** | Display name in the “From” field. |
| **EnableSsl** | `true` for TLS/SSL. |

## 2. **Keep secrets out of source control**

- **Development:** Use [User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets):
  ```bash
  dotnet user-secrets set "Smtp:Password" "your-app-password"
  dotnet user-secrets set "Smtp:UserName" "your-email@gmail.com"
  ```
  Leave `Smtp:Host` etc. in `appsettings.Development.json` or user secrets as needed.

- **Production:** Use environment variables or a secure vault (e.g. Azure Key Vault).  
  Example env vars: `Smtp__Host`, `Smtp__Port`, `Smtp__UserName`, `Smtp__Password`, `Smtp__FromEmail`, `Smtp__FromName`, `Smtp__EnableSsl` (double underscore `__` for nested keys in .NET config).

## 3. **Gmail**

- Turn on 2FA for the Google account.
- Create an **App Password**: Google Account → Security → 2-Step Verification → App passwords.
- Use that App Password in `Smtp:Password` and your Gmail address in `Smtp:UserName` / `Smtp:FromEmail`.
- Host: `smtp.gmail.com`, Port: `587`, EnableSsl: `true`.

## 4. **Summary**

- **Where:** `appsettings.json` → **`Smtp`** section, or User Secrets / environment variables.
- **Required to send email:** At least **`Smtp:Host`** (and usually **UserName** + **Password**). If `Host` is empty, the app skips sending and logs a warning.
