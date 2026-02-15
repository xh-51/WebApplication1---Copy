using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Middleware;

/// <summary>
/// Ensures only the most recent login session is valid per user.
/// If the same account logs in from another browser/device, this middleware
/// signs out the previous session on its next request and redirects to login.
/// </summary>
public class SingleSessionMiddleware
{
    private readonly RequestDelegate _next;

    public SingleSessionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AuditLogService auditLogService)
    {
        // Only check authenticated users
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            await _next(context);
            return;
        }

        // Skip check on Login, Logout, and Verify2FA so 2FA flow and login flow are not invalidated
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
        if (path.Contains("/account/login") || path.Contains("/account/logout") || path.Contains("/account/verify2fa"))
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

        // If we have a stored session and it doesn't match this request, this is an old session
        if (!string.IsNullOrEmpty(allowedSessionId) && allowedSessionId != currentSessionId)
        {
            var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();
            await signInManager.SignOutAsync();
            context.Session.Clear();
            ClearSessionCookie(context);
            ClearAuthCookie(context);
            context.Response.Redirect("/Account/SessionInvalidated");
            return;
        }

        await _next(context);
    }

    private static void ClearSessionCookie(HttpContext context)
    {
        const string sessionCookieName = ".AspNetCore.Session";
        context.Response.Cookies.Delete(sessionCookieName, new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = context.Request.IsHttps
        });
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
