# Deleting Identity and Session Cookies – When and How

This report describes **when** you must delete both the Identity auth cookie and the Session cookie, and **how** to delete them so the browser actually removes them. Use it to implement or audit cookie cleanup without looking at the existing code.

---

## 1. The Two Cookies

| Cookie | Default name | Purpose |
|--------|----------------|--------|
| **Identity (auth)** | `.AspNetCore.Identity.Application` | Holds the signed-in user. While present and valid, `User.Identity.IsAuthenticated` is true. |
| **Session** | `.AspNetCore.Session` | Holds the session ID; server uses it to look up session data (e.g. UserId, SessionId). |

**Rule:** Whenever the user is no longer considered logged in (logout, timeout, session invalidated), you must **delete both** cookies in the response. If you only call `SignOutAsync()` or `Session.Clear()`, the browser may still send the cookies until they expire. Deleting them with matching options ensures the browser drops them immediately.

---

## 2. How to Delete Them

### 2.1 Options must match how the cookies were set

To remove a cookie, the response must send a **Set-Cookie** that has the **same name, Path, and (for Secure) same Secure value** as when the cookie was set. Otherwise the browser may not remove it.

Use these options every time you delete either cookie:

- **Path**: `/`
- **HttpOnly**: `true`
- **SameSite**: `SameSiteMode.Strict` (or whatever your app uses)
- **Secure**: `context.Request.IsHttps` (so in HTTP dev you don’t require Secure; in HTTPS you do)

### 2.2 Two helpers – use the same logic everywhere

Implement two methods and call them from every place that needs to clear cookies (e.g. Account controller and any middleware that invalidates the session).

**ClearSessionCookie(context)**

- Call: `context.Response.Cookies.Delete(".AspNetCore.Session", options)`
- Use the options above (Path `/`, HttpOnly, SameSite, Secure from request).

**ClearAuthCookie(context)**

- Call: `context.Response.Cookies.Delete(".AspNetCore.Identity.Application", options)`
- Use the same options.

Example (C#):

```csharp
private static void ClearSessionCookie(HttpContext context)
{
    context.Response.Cookies.Delete(".AspNetCore.Session", new CookieOptions
    {
        Path = "/",
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps
    });
}

private static void ClearAuthCookie(HttpContext context)
{
    context.Response.Cookies.Delete(".AspNetCore.Identity.Application", new CookieOptions
    {
        Path = "/",
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps
    });
}
```

If your app uses different cookie names (e.g. custom Identity cookie name), use those names instead.

---

## 3. All Occasions When Both Cookies Must Be Deleted

In each case below, do **all** of:

1. **SignOutAsync()** (so Identity marks the user as signed out and stops issuing the auth cookie).
2. **HttpContext.Session.Clear()** (clear in-memory session for this request).
3. **ClearSessionCookie(context)** (tell the browser to remove the session cookie).
4. **ClearAuthCookie(context)** (tell the browser to remove the auth cookie).

Order can vary slightly (e.g. clear session then cookies, then SignOut), but all four must happen in the same request when the user is being “logged out” or “session invalidated.”

---

### Occasion 1: User lands on Login with “forced logout” query

**When:** The user is sent to the Login page **because** of session timeout or session invalidation (e.g. login from another device). The URL has a query parameter such as `?sessionExpired=true` or `?sessionInvalidated=1`.

**Where:** In the **Login GET** action.

**Steps:**

1. Read the query (e.g. `sessionExpired=true` or `sessionInvalidated=1`).
2. If either is present:
   - If `User.Identity?.IsAuthenticated == true`, call `await SignOutAsync()`.
   - Call `HttpContext.Session.Clear()`.
   - Call **ClearSessionCookie(HttpContext)**.
   - Call **ClearAuthCookie(HttpContext)**.
3. Optionally set TempData messages (“Your session has expired” / “You were signed out because you logged in elsewhere”).
4. Return the Login view.

**Why:** The client (or middleware) has redirected here after timeout or invalidation. The browser may still be sending the old auth and session cookies. Deleting both on this request ensures the browser drops them and the user is clearly logged out.

---

### Occasion 2: User clicks Logout

**When:** The user explicitly logs out (e.g. submits the logout form or hits the logout endpoint).

**Where:** In the **Logout** action (typically POST).

**Steps:**

1. Optionally log or audit the logout (e.g. write to audit log).
2. Call `HttpContext.Session.Clear()`.
3. Call **ClearSessionCookie(HttpContext)**.
4. Call `await SignOutAsync()`.
5. Call **ClearAuthCookie(HttpContext)**.
6. Redirect to Login (or home).

**Why:** Logout must end the session and remove both cookies so the next request is unauthenticated and has no session.

---

### Occasion 3: Single-session invalidation (“logged in elsewhere”)

**When:** You enforce “only one session per user” and you detect that the current request’s session is **not** the allowed one (e.g. user logged in on another device; the “allowed” session is the latest Login/2FA Login/Register).

**Where:** In the middleware that performs this check (e.g. single-session middleware), on the same request where you decide to invalidate.

**Steps:**

1. Call `await SignOutAsync()` (resolve `SignInManager` from `context.RequestServices` if needed).
2. Call `context.Session.Clear()`.
3. Call **ClearSessionCookie(context)**.
4. Call **ClearAuthCookie(context)**.
5. Redirect to Login with a query parameter (e.g. `/Account/Login?sessionInvalidated=1`) and **do not** call `_next` (short-circuit the pipeline).

**Why:** The user is no longer allowed to use this session. Both cookies must be removed so this browser is fully logged out; redirecting to Login with a query allows the Login GET (Occasion 1) to run the same cleanup again if needed.

---

### Occasion 4 (optional): Protected page detects “no session data”

**When:** A protected page (e.g. Dashboard, Home when “logged in”) checks something stored in session (e.g. `UserId`). You find that the session data is missing (`Session.GetString("UserId") == null`) but the user is still authenticated (auth cookie still valid).

**Where:** In the controller action for that page (e.g. Dashboard Index, Home Index).

**Steps:**

1. Call `await SignOutAsync()` so the auth cookie is cleared in the response.
2. Optionally call `HttpContext.Session.Clear()`, **ClearSessionCookie**, and **ClearAuthCookie** for consistency (so both cookies are gone in one place).
3. Set TempData (e.g. “Your session has expired”).
4. Redirect to Login.

**Why:** The session has already expired (e.g. IdleTimeout). SignOutAsync removes the auth cookie. Explicitly deleting both cookies here keeps behavior consistent with Occasions 1–3 and avoids leaving the session cookie in the browser. If you prefer, you can only SignOutAsync and redirect to Login, and rely on the client or a later request to hit Login with `sessionExpired=true` so Occasion 1 deletes both cookies.

---

## 4. Summary Table

| Occasion | Where | SignOutAsync | Session.Clear | ClearSessionCookie | ClearAuthCookie | Redirect |
|----------|--------|--------------|----------------|--------------------|-----------------|----------|
| 1. Login with sessionExpired / sessionInvalidated | Login GET | If authenticated | Yes | Yes | Yes | No (return view) |
| 2. Logout | Logout POST | Yes | Yes | Yes | Yes | To Login |
| 3. Single-session invalidation | Middleware | Yes | Yes | Yes | Yes | To Login?sessionInvalidated=1 |
| 4. No session data on protected page | e.g. Dashboard/Home | Yes | Optional | Optional | Optional | To Login |

For a minimal, consistent implementation, use **all four steps** (SignOutAsync, Session.Clear, ClearSessionCookie, ClearAuthCookie) in occasions 1–3. For occasion 4, at least SignOutAsync and redirect; adding the two cookie deletes matches the other occasions.

---

## 5. Checklist for Implementation / Audit

- [ ] Two helpers implemented: **ClearSessionCookie** and **ClearAuthCookie** with Path `/`, HttpOnly, SameSite, Secure from request.
- [ ] **Login GET:** If query has sessionExpired or sessionInvalidated → SignOut (if authenticated), Session.Clear, both cookie deletes, then return Login view.
- [ ] **Logout:** Session.Clear, ClearSessionCookie, SignOutAsync, ClearAuthCookie, redirect to Login.
- [ ] **Single-session middleware:** When current session is not allowed → SignOutAsync, Session.Clear, both cookie deletes, redirect to Login?sessionInvalidated=1.
- [ ] **Protected pages (optional):** When session data (e.g. UserId) is null but user is authenticated → SignOutAsync and optionally Session.Clear + both cookie deletes, redirect to Login.

Using this, Identity and Session cookies are deleted in all situations where the user must no longer be considered logged in.
