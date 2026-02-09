# Auto Session Lockout + Identity Cookie Clear – Full Implementation Guide

This document describes how to implement in another ASP.NET Core project:

1. **Single session per account** – New login from another browser/device locks out the previous session.
2. **Session timeout** – Inactivity timer (e.g. 1 minute) with client redirect and server cookie expiry.
3. **Clearing the Identity auth cookie** – On any logout (manual, timeout redirect, or single-session lockout) so `.AspNetCore.Identity.Application` is removed in the browser.

---

## Prerequisites

- ASP.NET Core with **Identity** (e.g. `AddIdentity`, `AddEntityFrameworkStores`).
- **Session** middleware (`AddSession`, `UseSession`).
- A way to record **Login** and **Register** with a **SessionId** (e.g. an `AuditLog` table with `UserId`, `Action`, `SessionId`, `Timestamp`).

---

## 1. Database: Audit log with SessionId

You need one row per “login event” with the **session ID** so we can treat “latest Login/Register” as the only valid session.

### Model (e.g. `Models/AuditLog.cs`)

```csharp
using System.ComponentModel.DataAnnotations;

namespace YourProject.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required]
        public string UserEmail { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        public string Action { get; set; } = string.Empty;  // "Login", "Register", etc.

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        public string IpAddress { get; set; } = string.Empty;

        [StringLength(500)]
        public string? UserAgent { get; set; }

        [StringLength(100)]
        public string? SessionId { get; set; }   // Required for single-session

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}
```

### DbContext

- Add `DbSet<AuditLog> AuditLogs`.
- In `OnModelCreating`: index `UserId`, `Timestamp`, `SessionId` (and add `AuditLog` to your migrations).

---

## 2. AuditLogService: log with SessionId + “current session” lookup

Your audit service must:

- Write **SessionId** on every log (from `HttpContext.Session.Id`).
- Expose a method that returns the **SessionId of the most recent Login or Register** for a user (that session is the only valid one).

Example:

```csharp
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
// ... your DbContext and AuditLog namespace

public class AuditLogService
{
    private readonly ApplicationDbContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuditLogService(ApplicationDbContext context, IHttpContextAccessor httpContextAccessor)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task LogActivityAsync(string userId, string userEmail, string action, string? description = null)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null) return;

        try
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                UserEmail = userEmail,
                Action = action,
                Description = description,
                IpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                UserAgent = httpContext.Request.Headers["User-Agent"].ToString(),
                SessionId = httpContext.Session.Id,  // Important
                Timestamp = DateTime.UtcNow
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
        catch { /* don't break login/register if audit fails */ }
    }

    /// <summary>
    /// SessionId of the most recent Login or Register for this user. Only that session is valid.
    /// </summary>
    public async Task<string?> GetCurrentSessionIdAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId)) return null;
        try
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId && (a.Action == "Login" || a.Action == "Register"))
                .OrderByDescending(a => a.Timestamp)
                .Select(a => a.SessionId)
                .FirstOrDefaultAsync();
        }
        catch
        {
            return null;
        }
    }
}
```

Register in `Program.cs` (or Startup):

- `builder.Services.AddHttpContextAccessor();`
- `builder.Services.AddScoped<AuditLogService>();` (or your usual scope).

---

## 3. Single-session middleware

This runs **after** `UseAuthentication()` and `UseAuthorization()`. For each authenticated request (except Login/Logout), it checks whether the current request’s session is the “current” session for that user; if not, it signs out, clears session, clears the auth cookie, and redirects to Login.

Create `Middleware/SingleSessionMiddleware.cs`:

```csharp
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using YourProject.Models;   // ApplicationUser
using YourProject.Services; // AuditLogService

namespace YourProject.Middleware
{
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;

        public SingleSessionMiddleware(RequestDelegate next) => _next = next;

        public async Task InvokeAsync(HttpContext context, AuditLogService auditLogService)
        {
            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                await _next(context);
                return;
            }

            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            if (path.Contains("/account/login") || path.Contains("/account/logout"))
            {
                await _next(context);
                return;
            }

            var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? context.User.FindFirst("sub")?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                await _next(context);
                return;
            }

            var currentSessionId = context.Session.Id;
            var allowedSessionId = await auditLogService.GetCurrentSessionIdAsync(userId);

            if (!string.IsNullOrEmpty(allowedSessionId) && allowedSessionId != currentSessionId)
            {
                var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();
                await signInManager.SignOutAsync();
                context.Session.Clear();
                ClearAuthCookie(context);
                context.Response.Redirect("/Account/Login?sessionInvalidated=1");
                return;
            }

            await _next(context);
        }

        private static void ClearAuthCookie(HttpContext context)
        {
            const string cookieName = ".AspNetCore.Identity.Application";
            context.Response.Cookies.Delete(cookieName, new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Secure = context.Request.IsHttps
            });
        }
    }
}
```

Adjust `/account/login` and `/account/logout` paths if your routes differ.

---

## 4. Program.cs (or Startup): Session, cookie timeout, middleware order

- **Session**: required for `Session.Id` and single-session checks.

```csharp
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);  // Match your desired timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
```

- **Identity cookie** (session timeout and sliding expiry):

```csharp
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(1);  // Match session timeout
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
```

- **Pipeline order** (critical):

```csharp
app.UseStaticFiles();
app.UseSession();        // Before routing
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<SingleSessionMiddleware>();  // After auth
app.MapControllerRoute(/* ... */);
```

---

## 5. AccountController: Login GET – clear cookie on timeout / session invalidated

When the user lands on Login with `sessionExpired=true` or `sessionInvalidated=1`, always clear the auth cookie (and sign out if still authenticated). This fixes the case where the client redirects after timeout but the server already considered the session expired, so the cookie was never cleared.

```csharp
[HttpGet]
public async Task<IActionResult> Login(string sessionExpired)
{
    var sessionInvalidated = Request.Query["sessionInvalidated"].FirstOrDefault() == "1";
    var forcedLogout = sessionExpired == "true" || sessionInvalidated;

    if (forcedLogout)
    {
        if (User.Identity?.IsAuthenticated == true)
            await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();
        ClearAuthCookie(HttpContext);
    }

    if (sessionExpired == "true")
        TempData["SessionExpired"] = "Your session has expired. Please login again.";
    if (sessionInvalidated)
        TempData["SessionInvalidated"] = "You have been signed out because you logged in from another device or browser.";

    return View();
}

private static void ClearAuthCookie(HttpContext context)
{
    const string cookieName = ".AspNetCore.Identity.Application";
    context.Response.Cookies.Delete(cookieName, new CookieOptions
    {
        Path = "/",
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps
    });
}
```

If you use a custom cookie name in `ConfigureApplicationCookie(options => options.Cookie.Name = "...")`, use that same name in `ClearAuthCookie`.

---

## 6. AccountController: Login POST – set session and log "Login"

After a successful sign-in (and after 2FA if you have it), set session and log with action **"Login"** so `GetCurrentSessionIdAsync` sees this as the new “current” session.

```csharp
// After PasswordSignInAsync succeeded (and not 2FA flow):
HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);
HttpContext.Session.SetString("UserId", user.Id);

await _auditLogService.LogActivityAsync(
    user.Id,
    user.Email ?? "",
    "Login",
    "User successfully logged in"
);
```

Do the same after 2FA verification (set session + log "Login" with current `HttpContext.Session.Id`).

---

## 7. AccountController: Register – set session and log "Register"

After creating the user and before or after `SignInAsync`, set session and log **"Register"** so the first login after register is also the “current” session.

```csharp
HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);
HttpContext.Session.SetString("UserId", user.Id);

await _auditLogService.LogActivityAsync(
    user.Id,
    user.Email ?? "",
    "Register",
    "User successfully registered"
);
await _signInManager.SignInAsync(user, isPersistent: false);
```

---

## 8. AccountController: Logout – clear session and auth cookie

On manual logout, clear session, sign out, and remove the cookie so the browser drops it.

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    // Optional: audit log
    HttpContext.Session.Clear();
    await _signInManager.SignOutAsync();
    ClearAuthCookie(HttpContext);
    return RedirectToAction("Login");
}
```

---

## 9. Client-side session timeout (e.g. in Layout or Dashboard)

Redirect to Login with `sessionExpired=true` after inactivity so the server can clear the cookie on that request.

```html
@if (User.Identity?.IsAuthenticated == true)
{
    <script>
        var sessionTimeout = 1 * 60 * 1000;   // 1 minute (match server ExpireTimeSpan)
        var warningMs = 30 * 1000;             // warn 30 seconds before
        var timeoutTimer = setTimeout(function() {
            alert('Your session will expire in 30 seconds. Please save your work.');
        }, sessionTimeout - warningMs);
        var expireTimer = setTimeout(function() {
            window.location.href = '/Account/Login?sessionExpired=true';
        }, sessionTimeout);
        function resetSessionTimer() {
            clearTimeout(timeoutTimer);
            clearTimeout(expireTimer);
            timeoutTimer = setTimeout(function() {
                alert('Your session will expire in 30 seconds. Please save your work.');
            }, sessionTimeout - warningMs);
            expireTimer = setTimeout(function() {
                window.location.href = '/Account/Login?sessionExpired=true';
            }, sessionTimeout);
        }
        document.addEventListener('mousemove', resetSessionTimer);
        document.addEventListener('keypress', resetSessionTimer);
        document.addEventListener('click', resetSessionTimer);
    </script>
}
```

Put this on every page that requires an authenticated session (e.g. in `_Layout.cshtml` inside the authenticated block, or on Dashboard/Home).

---

## 10. Login view: show messages

Display the TempData messages set in Login GET:

```html
@if (TempData["SessionExpired"] != null)
{
    <div class="alert alert-warning">@TempData["SessionExpired"]</div>
}
@if (TempData["SessionInvalidated"] != null)
{
    <div class="alert alert-warning">@TempData["SessionInvalidated"]</div>
}
```

---

## Summary checklist

| Piece | Purpose |
|-------|--------|
| **AuditLog.SessionId** | Store which session performed Login/Register. |
| **AuditLogService.LogActivityAsync** | Always pass `HttpContext.Session.Id` into the log. |
| **AuditLogService.GetCurrentSessionIdAsync** | Return latest Login/Register SessionId for a user. |
| **SingleSessionMiddleware** | If current request’s session ≠ allowed session → sign out, clear session, clear cookie, redirect to Login?sessionInvalidated=1. |
| **ClearAuthCookie** | Delete `.AspNetCore.Identity.Application` with Path=/, SameSite=Strict, etc., on every logout path. |
| **Login GET** | On sessionExpired or sessionInvalidated → sign out (if needed), clear session, **always** clear auth cookie. |
| **Login POST** | After success: set SessionId/UserId in session, log "Login". |
| **Register** | After create: set SessionId/UserId, log "Register", then SignIn. |
| **Logout** | Session.Clear, SignOutAsync, ClearAuthCookie, redirect to Login. |
| **Client script** | After timeout, redirect to `/Account/Login?sessionExpired=true`. |
| **Program.cs** | UseSession, ConfigureApplicationCookie (ExpireTimeSpan, SlidingExpiration), UseAuthentication, UseAuthorization, **then** SingleSessionMiddleware. |

With this, a new login from another browser makes the previous session get a redirect and cookie clear on next request, and any timeout redirect to Login also clears the Identity cookie so you no longer see `.AspNetCore.Identity.Application` after auto logout.
