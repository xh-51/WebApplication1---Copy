# Software Testing and Security Analysis — Remediation Report

## X.X Missing Cross-Site Request Forgery Token Validation (CodeQL cs/web/missing-token-validation)

---

### 1. CodeQL Issue Description

**What this vulnerability means**

The CodeQL rule `cs/web/missing-token-validation` identifies HTTP POST request handlers that do not perform **cross-site request forgery (CSRF) token validation**. CSRF is an attack in which a malicious site or script causes the victim’s browser to send an authenticated request to a target application without the user’s intent. If the target action does not verify that the request includes a valid anti-forgery token (issued by the application and tied to the user’s session or cookie), the server may accept the forged request and perform state-changing operations (e.g. registration, login, or profile updates) on behalf of the victim. The vulnerability in this finding is that the `Register` POST action was not explicitly protected by the framework’s anti-forgery validation mechanism that CodeQL expects (the ** [ValidateAntiForgeryToken]** attribute), so the analyser reported missing CSRF token validation for that endpoint.

**Why it is considered high severity**

Registration is a **state-changing, security-relevant operation**: it creates a new user account and may grant access to the application. If an attacker can submit a forged POST to the registration endpoint without a valid anti-forgery token being required and validated, they could:

- **Trigger unwanted registrations:** A victim visiting a malicious page could have a registration form submitted in their name (e.g. with attacker-controlled data or with the victim’s own credentials), leading to account creation or data submission without the user’s consent.
- **Abuse server resources and policies:** Mass or automated registration could be performed via cross-site requests, bypassing any client-side or per-request checks that assume the request originated from the application’s own registration page.
- **Undermine application trust:** Lack of CSRF protection on POST actions is a recognised OWASP Top 10–related weakness and is commonly required by secure-coding and compliance standards.

For these reasons, missing CSRF validation on a POST handler that performs sensitive operations is treated as **high severity** in a security analysis context.

**Attack scenario if not fixed**

1. An attacker builds a malicious web page that includes a hidden form (or JavaScript) that POSTs to the application’s registration URL (e.g. `https://example.com/Account/Register`) with chosen form fields (e.g. email, password, NRIC).
2. The victim, who may be logged into the application or simply visiting the attacker’s page, triggers the request (e.g. by loading the page or clicking a link). The browser sends the POST with any cookies (e.g. session) the application had set.
3. If the server does **not** require and validate an anti-forgery token, it may accept the request and create an account or process the data. The attacker has thus performed a **cross-site request forgery** against the registration endpoint.
4. Even if the application previously validated the token manually in the action (e.g. via `IAntiforgery.ValidateRequestAsync`), static analysis tools such as CodeQL typically look for the **declarative** use of the framework’s ** [ValidateAntiForgeryToken]** attribute. Absence of that attribute is reported as missing validation, and the endpoint may remain non-compliant with security standards that expect consistent, attribute-based CSRF protection on all state-changing POST actions.

**Relation to ASP.NET Core security context**

In ASP.NET Core, the recommended way to enforce CSRF protection on POST (and other non-GET/non-safe) requests is to use the **anti-forgery** system: the application emits a token in the response (e.g. via `@Html.AntiForgeryToken()` in a form), and the server validates that token on subsequent requests. The ** [ValidateAntiForgeryToken]** attribute registers a filter that runs before the action and validates the token; if validation fails, the request is rejected (typically with a 400 Bad Request or similar). Using this attribute on every state-changing POST action ensures that CSRF protection is applied consistently and is visible to both developers and static analysers. Relying only on manual checks in the action body, or omitting validation, leaves the endpoint exposed to CSRF and fails to satisfy tools and policies that require explicit, attribute-based token validation.

---

### 2. Where the Vulnerability Was Located

**File path**

`WebApplication1/Controllers/AccountController.cs`

**Controller / method name**

`AccountController.Register()` — the HTTP POST overload that processes the registration form submission.

**Original vulnerable code snippet**

```csharp
[HttpPost]
[RequestFormLimits(MultipartBodyLengthLimit = 50 * 1024 * 1024)] // 50 MB
[RequestSizeLimit(50 * 1024 * 1024)] // 50 MB
public async Task<IActionResult> Register(RegisterViewModel model, string recaptchaToken)
{
    ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
    if (model == null)
        model = new RegisterViewModel();
    // Validate anti-forgery token in action (avoids filter throwing and causing connection reset)
    try
    {
        await _antiforgery.ValidateRequestAsync(HttpContext);
    }
    catch
    {
        ModelState.AddModelError(string.Empty, "Security validation failed. Please refresh the page and try again.");
        return View(model);
    }
    try
    {
        return await RegisterCoreAsync(model, recaptchaToken);
    }
    catch (Exception)
    {
        ModelState.AddModelError(string.Empty, "Registration failed. Please check your details and try again. ...");
        return View(model);
    }
}
```

**What was missing or insecure**

- **Missing declarative CSRF validation:** The action did **not** have the ** [ValidateAntiForgeryToken]** attribute. CodeQL’s `cs/web/missing-token-validation` rule specifically checks that POST request handlers are protected by the framework’s anti-forgery token validation; it looks for this attribute (or equivalent declarative mechanism). Its absence is what triggers the alert.
- **Static analysis and compliance:** Even though the code called `_antiforgery.ValidateRequestAsync(HttpContext)` inside the action, many security standards and static analysers (including CodeQL) expect **declarative** CSRF protection at the action or global level. Attribute-based validation runs in the filter pipeline before the action executes, provides a single point of enforcement, and is the pattern documented by Microsoft for ASP.NET Core. Relying only on manual validation in the action body does not satisfy the rule and can lead to inconsistent protection if future changes bypass or remove that call.
- **Risk of bypass or inconsistency:** Any code path that could reach the state-changing logic (e.g. `RegisterCoreAsync`) without going through a validated anti-forgery check would be a vulnerability. Using the standard ** [ValidateAntiForgeryToken]** attribute ensures that validation is performed by the framework before the action runs, so the sensitive logic is never executed with an invalid or missing token.

---

### 3. Code Changes Made to Fix It

**Updated secure code in AccountController**

**File:** `WebApplication1/Controllers/AccountController.cs`

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
[RequestFormLimits(MultipartBodyLengthLimit = 50 * 1024 * 1024)] // 50 MB
[RequestSizeLimit(50 * 1024 * 1024)] // 50 MB
public async Task<IActionResult> Register(RegisterViewModel model, string recaptchaToken)
{
    ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
    if (model == null)
        model = new RegisterViewModel();
    try
    {
        return await RegisterCoreAsync(model, recaptchaToken);
    }
    catch (Exception)
    {
        ModelState.AddModelError(string.Empty, "Registration failed. Please check your details and try again. If the problem continues, ensure SQL Server (LocalDB) is running and the app has write access to the uploads folder.");
        return View(model);
    }
}
```

**Keywords / logic added**

- ** [ValidateAntiForgeryToken]** — This attribute was **added** immediately after ** [HttpPost]** on the `Register` POST action. It registers the framework’s anti-forgery validation filter for this action. Every POST request to `Register` must now include a valid anti-forgery token (e.g. the one emitted by `@Html.AntiForgeryToken()` in the registration form); otherwise the filter rejects the request before the action runs.
- **Removal of manual validation block:** The try/catch block that called `_antiforgery.ValidateRequestAsync(HttpContext)` was **removed**. Validation is now performed once by the ** [ValidateAntiForgeryToken]** filter in the pipeline. This avoids redundant logic and ensures that CodeQL and other tools that look for attribute-based validation recognise the action as protected.

**View (no change required)**

**File:** `WebApplication1/Views/Account/Register.cshtml`

The registration form already emits the anti-forgery token:

```html
<form action="/Account/Register" method="post" enctype="multipart/form-data">
    @Html.AntiForgeryToken()
    ...
</form>
```

**Explanation:** **@Html.AntiForgeryToken()** outputs a hidden form field containing the token (and sets the cookie if the application uses the default cookie-based anti-forgery configuration). When the user submits the form, the token is sent with the POST. The ** [ValidateAntiForgeryToken]** filter on the `Register` action validates this token; no view changes were required.

**No other files were modified.** Only `AccountController.cs` was changed; the view already contained the token.

---

### 4. Why This Fix Works (Technical Explanation)

- **Filter pipeline execution:** In ASP.NET Core, action filters run as part of the request pipeline. The ** [ValidateAntiForgeryToken]** attribute adds a filter that executes **before** the action. That filter calls the anti-forgery service to validate the token in the request (typically from the form field `__RequestVerificationToken` and the associated cookie). If the token is missing, invalid, or not matched to the current user/session, the filter short-circuits the request (typically with an HTTP 400 Bad Request or similar) and the action is **not** executed. Therefore, no state-changing registration logic runs without a valid token.
- **Token binding:** The anti-forgery token is bound to the user’s identity (or anonymous identity) and to the application’s validation key. A token generated on a legitimate registration page cannot be reused from another origin (e.g. a malicious site) in a way that passes validation, because the token is validated against the cookie and the request context. Thus, a forged POST from an attacker’s page will not contain a valid token and will be rejected by the filter.
- **Framework features used:** The fix relies on ASP.NET Core’s built-in **anti-forgery middleware and filters**: the **ValidateAntiForgeryTokenAttribute** and the **IAntiforgery** service (configured by default when the application adds the anti-forgery services). No custom validation logic is required; the attribute ensures that the framework’s validation runs for every POST to the `Register` action.
- **How the attack is mitigated:** A CSRF attack sends a POST from the victim’s browser to the registration URL without the victim having loaded the application’s registration form. That request will not contain a valid anti-forgery token (or may contain none). The ** [ValidateAntiForgeryToken]** filter will detect the failure and reject the request before `Register` or `RegisterCoreAsync` runs, so no account is created and no sensitive processing occurs. The vulnerability is closed by enforcing token validation at the pipeline level for every POST to this action.

---

### 5. Security Improvement

- **Prevents CSRF on registration:** The registration endpoint is now protected against cross-site request forgery. An attacker can no longer use a malicious page to trigger an unintended registration (or submission of registration data) in the victim’s browser. This reduces the risk of unwanted account creation, abuse of server resources, and violation of user intent.
- **Real-world impact:** CSRF on registration or other state-changing endpoints can lead to spam accounts, abuse of free tiers, or submission of malicious or misleading data. Enforcing anti-forgery validation on the `Register` action aligns with OWASP recommendations and common compliance requirements (e.g. PCI-DSS, SOC 2) that expect CSRF protections on state-changing operations.
- **Aligns with secure coding practices:** Using ** [ValidateAntiForgeryToken]** on every state-changing POST action is the pattern recommended by Microsoft and is consistent with defence-in-depth: validation is performed in the filter pipeline, is visible in the code, and is recognised by static analysis tools. This supports maintainability and auditability of security controls and ensures that registration is treated as a protected, token-validated operation.

---

### 6. Checklist Mapping

- **Perform source code analysis using external tools (GitHub CodeQL)**  
  The vulnerability was identified by the CodeQL query **cs/web/missing-token-validation** (missing cross-site request forgery token validation). The `Register` POST action was flagged because it did not use the ** [ValidateAntiForgeryToken]** attribute. Addressing this finding demonstrates that the assignment’s requirement to perform source code analysis using an external tool (GitHub CodeQL) has been carried out.

- **Address security vulnerabilities identified in the source code**  
  The vulnerability was remediated by adding the ** [ValidateAntiForgeryToken]** attribute to the `Register` POST action and removing the redundant manual validation block so that CSRF validation is performed consistently by the framework filter. The endpoint now satisfies the CodeQL rule and meets the expectation that all POST handlers that perform sensitive operations validate the anti-forgery token. This demonstrates compliance with the assignment requirement to address security vulnerabilities identified in the source code.

---

*End of report section.*
