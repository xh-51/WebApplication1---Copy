# Software Testing and Security Analysis — Remediation Report

## X.X Information Exposure Through Transmitted Data (CodeQL cs/sensitive-data-transmission)

---

### 1. CodeQL Issue Description

**What this vulnerability means**

The CodeQL rule **cs/sensitive-data-transmission** identifies code paths where **sensitive information** is **transmitted** in a way that could expose it to the wrong party or in an inappropriate context. The rule states that transmitting sensitive data to the user is a potential security risk and that transmitted data must be intended for the recipient. Examples given include passwords and the contents of database exceptions, which should not be sent to the user because they can be abused or exploited. In this finding, the analyser flagged the construction and sending of an email message (in `EmailSender.SendEmailAsync`) where the **data transmitted** (the email body, subject, and recipient) **depends on sensitive information**. That can mean: (1) the email content is built from or includes sensitive data (e.g. a password reset token or URL) that could be misused if exposed to the wrong party or in logs; or (2) when sending fails, the **exception** (which may contain sensitive details such as SMTP configuration or network information) is rethrown and could propagate to the HTTP response or caller, thus being “transmitted” to the user. In both cases, the concern is **information exposure through transmitted data**.

**Why it is considered high severity**

Exposing sensitive data through transmission can lead to:

- **Abuse of security tokens:** If a password reset link or token is logged, cached, or sent to an unintended recipient, an attacker could use it to take over an account.
- **Leakage of system details:** Exception messages or stack traces can reveal server paths, configuration, or dependency versions, aiding further attacks.
- **Violation of confidentiality:** Passwords, tokens, or personal data must only be sent to the intended recipient (e.g. the user’s own email) and must not appear in logs, error pages, or other channels.

For these reasons, CodeQL treats such patterns as security-relevant and the finding is addressed as **high severity** in a security analysis context.

**Attack scenario if not fixed**

1. **Exception details transmitted to the user:** If `SendEmailAsync` fails (e.g. SMTP error), the original exception is rethrown. If that exception is eventually returned to the HTTP client (e.g. by a global exception handler that includes the message or by a developer error page), the response could contain sensitive information (e.g. “Authentication failed for user …”, host names, or port numbers). An attacker could trigger repeated failures and harvest such data from error responses.
2. **Sensitive data in a generic channel:** If the email body and subject are built by the caller and passed into `SendEmailAsync`, any caller could pass exception text, passwords, or other secrets. That data would then be sent over SMTP and might be logged (e.g. in the “subject” or “to” parameters already logged). Concentrating sensitive content (e.g. reset link) in a **dedicated** method with a fixed template ensures the link is only sent to the intended recipient and is not mixed with arbitrary caller-supplied content that could leak.

**Relation to ASP.NET Core security context**

In ASP.NET Core, services that send email or other outbound data must ensure that **only intended, non-sensitive content** is transmitted and that **errors do not expose internal details** to the client. Best practice is to use dedicated methods for transactional emails (e.g. password reset) so that sensitive parameters (e.g. callback URL) are used only inside the service with a fixed template, and to replace rethrown exceptions with **generic** exceptions so that sensitive exception details are not transmitted to the caller or the HTTP response.

---

### 2. Where the Vulnerability Was Located

**File path**

`WebApplication1/Services/EmailSender.cs`

**Class / method name**

`EmailSender.SendEmailAsync(string to, string subject, string htmlBody)` — the method that builds and sends the SMTP email.

**Original vulnerable code snippet**

```csharp
using var message = new MailMessage
{
    From = new MailAddress(fromEmail, fromName),
    Subject = subject,
    Body = htmlBody,
    IsBodyHtml = true
};
message.To.Add(to);

await client.SendMailAsync(message);
_logger.LogInformation("Email sent to {To}, subject: {Subject}.", to, subject);
// ...
catch (Exception ex)
{
    _logger.LogError(ex, "Failed to send email to {To}, subject: {Subject}.", to, subject);
    throw;
}
```

**What was missing or insecure**

- **Data transmitted depended on caller-supplied content:** The `subject` and `htmlBody` (and `to`) were passed in from the caller. The only call site (ForgotPassword) passed a body that included the **password reset callback URL** (containing the token). CodeQL treats the email as “data transmitted to the user” and the body as “depending on sensitive information” (the token). Even when the recipient is the correct user, using a **generic** `SendEmailAsync(to, subject, htmlBody)` allows any caller to pass arbitrary sensitive content, and the data flow is harder for static analysis to approve.
- **Exception rethrow:** After logging, the code used **`throw;`**, which rethrows the **original exception**. That exception may contain sensitive information (e.g. SMTP authentication failure messages, host names, or stack traces). If it propagates to the HTTP client (e.g. via an error page or API response), that constitutes **information exposure through transmitted data**. The fix requires that the service **not** transmit the original exception to the caller; instead, it should throw a **generic** exception with a safe message.

---

### 3. Code Changes Made to Fix It

**3.1 New interface method and dedicated password-reset email**

**File:** `WebApplication1/Services/IEmailSender.cs`

```csharp
Task SendEmailAsync(string to, string subject, string htmlBody);

/// <summary>
/// Sends a password-reset email using a fixed template. The callback URL is sent only to the intended recipient (to).
/// Use this instead of passing a constructed body to SendEmailAsync to avoid sensitive data exposure.
/// </summary>
Task SendPasswordResetEmailAsync(string to, string callbackUrl);
```

**Keywords added:** **SendPasswordResetEmailAsync(string to, string callbackUrl)** — A dedicated method so that the **sensitive** callback URL is only ever used inside the email service with a **fixed template**, and only sent to the intended recipient (`to`). Callers no longer pass a pre-built body that contains the link.

**3.2 EmailSender: dedicated method, documentation, and generic exception**

**File:** `WebApplication1/Services/EmailSender.cs`

**Added at class level:**

- **Constant:** `private const string PasswordResetSubject = "Reset your Ace Job Agency password";` — Fixed subject so it is not caller-supplied.
- **Comment on class:** Instruction that callers must not pass sensitive data (passwords, exception messages, tokens in plain text) in `subject` or `htmlBody` when using `SendEmailAsync`, and to use dedicated methods (e.g. `SendPasswordResetEmailAsync`) for transactional emails.

**New method:**

```csharp
/// <summary>
/// Sends a password-reset email using a fixed template. The callback URL is sent only to the intended recipient.
/// This avoids passing sensitive data (reset link) through a generic channel and limits exposure to the recipient only.
/// </summary>
public async Task SendPasswordResetEmailAsync(string to, string callbackUrl)
{
    var htmlBody = $"Please reset your password by clicking <a href=\"{WebUtility.HtmlEncode(callbackUrl)}\">this secure link</a>. The link will expire after a short time.";
    await SendEmailAsync(to, PasswordResetSubject, htmlBody);
}
```

**Keywords / logic added:**

- **SendPasswordResetEmailAsync** — Builds the email **body inside the service** from a **fixed template**. The only variable is `callbackUrl`, which is **HtmlEncoded** via **WebUtility.HtmlEncode(callbackUrl)** before being embedded, reducing injection risk and making the data flow explicit.
- **PasswordResetSubject** — Subject is fixed in the service, not supplied by the caller.
- **WebUtility.HtmlEncode(callbackUrl)** — Encodes the URL before placing it in the HTML so that the transmitted data is safe and the sensitive URL is only used in this single, controlled context.

**Change in catch block of SendEmailAsync:**

**Before:**

```csharp
catch (Exception ex)
{
    _logger.LogError(ex, "Failed to send email to {To}, subject: {Subject}.", to, subject);
    throw;
}
```

**After:**

```csharp
catch (Exception ex)
{
    _logger.LogError(ex, "Failed to send email to {To}, subject: {Subject}.", to, subject);
    throw new InvalidOperationException("Failed to send email. Please try again later.");
}
```

**Keywords added:** **throw new InvalidOperationException("Failed to send email. Please try again later.")** — The **original exception is no longer rethrown**. Only a **generic** message is transmitted to the caller, so sensitive exception details (e.g. SMTP or network information) are not exposed.

**3.3 Controller: use dedicated method**

**File:** `WebApplication1/Controllers/AccountController.cs` (ForgotPassword POST)

**Before:**

```csharp
await _emailSender.SendEmailAsync(
    user.Email!,
    "Reset your Ace Job Agency password",
    $"Please reset your password by clicking <a href=\"{callbackUrl}\">this secure link</a>. The link will expire after a short time.");
```

**After:**

```csharp
await _emailSender.SendPasswordResetEmailAsync(user.Email!, callbackUrl);
```

**Explanation:** The controller no longer constructs the email body. It passes only the **recipient** and the **callback URL** to **SendPasswordResetEmailAsync**. The sensitive URL is only used inside the email service with a fixed template and is sent only to the intended recipient.

---

### 4. Why This Fix Works (Technical Explanation)

- **Dedicated method and fixed template:** By introducing **SendPasswordResetEmailAsync**, the application ensures that the **only** place the password reset callback URL is used for email is inside the email service, in a **fixed** HTML template. The data flow is: token → callbackUrl (in controller) → passed to SendPasswordResetEmailAsync → HtmlEncode and embedded in template → SendEmailAsync. Static analysis and code review can see that the sensitive URL is never passed as arbitrary “body” content and is only sent to the address supplied as `to` (the user’s own email). This satisfies the requirement that “transmitted data is intended for the user” and limits the use of sensitive data to a single, controlled path.
- **No transmission of exception details:** Replacing **`throw;`** with **`throw new InvalidOperationException("Failed to send email. Please try again later.")`** ensures that **no part of the original exception** (message, inner exception, or stack trace) is transmitted to the caller. If the caller or a global exception handler returns an error to the HTTP client, the client sees only the generic message. Sensitive details remain in server-side logs (via **LogError(ex, …)**) and are not exposed through transmitted data.
- **WebUtility.HtmlEncode:** Encoding the callback URL before embedding it in the HTML body prevents HTML/script injection and makes the transmitted content safe. It does not change the usability of the link for the intended recipient.
- **Framework and design:** The fix uses the same .NET email and logging APIs; it does not rely on new framework security features. The mitigation is **design-level**: isolate sensitive data in a dedicated method with a fixed template, and do not rethrow exceptions that might contain sensitive information. The attack (harvesting exception details or misusing a generic email channel for sensitive content) is mitigated because exception details are no longer transmitted and the reset link is only sent through the dedicated, template-based method to the intended recipient.

---

### 5. Security Improvement

- **Prevents information exposure:** Sensitive data (password reset link and exception details) are no longer transmitted in an uncontrolled or unsafe manner. The reset link is sent only via a dedicated method to the recipient’s email, and failure to send email results in a generic error message to the caller/client.
- **Real-world impact:** Reduces the risk of token leakage through logs or error responses, and of attackers harvesting SMTP or configuration details from exception messages. Aligns with OWASP and secure-coding guidance to avoid exposing sensitive data in responses or logs and to use dedicated, constrained paths for security-sensitive operations.
- **Aligns with secure coding practices:** The pattern of **dedicated methods for transactional emails** and **generic exceptions for failures** is a standard way to satisfy “no sensitive data transmission” and to pass static analysis (e.g. CodeQL) while keeping behaviour correct for the user.

---

### 6. Checklist Mapping

- **Perform source code analysis using external tools (GitHub CodeQL)**  
  The vulnerability was identified by the CodeQL query **cs/sensitive-data-transmission** (information exposure through transmitted data). The `EmailSender` construction and sending of the mail message, and the rethrow of the exception, were flagged. Addressing this finding demonstrates that the assignment’s requirement to perform source code analysis using an external tool (GitHub CodeQL) has been carried out.

- **Address security vulnerabilities identified in the source code**  
  The vulnerability was remediated by: (1) adding **SendPasswordResetEmailAsync** and using it from the controller so that sensitive data (callback URL) is only used in a fixed template and sent to the intended recipient; (2) replacing the exception rethrow with **throw new InvalidOperationException("…")** so that sensitive exception details are not transmitted. The endpoint and email service now comply with the intent of the CodeQL rule and with the assignment requirement to address security vulnerabilities identified in the source code.

---

*End of report section.*
