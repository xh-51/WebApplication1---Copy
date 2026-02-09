# Cookie Handling During Session Timeout – Implementation Guide

This document explains the design and how to implement it so you can build the same behavior without looking at the existing code. It is written for ASP.NET Core with Identity and session.

---

## 1. What You Are Implementing

**Goal:** After a period of inactivity (e.g. 1 minute), the user is treated as logged out. When that happens (or when they log out, or when you invalidate their session), the browser must **stop sending** the auth and session cookies. To achieve that, you must **explicitly delete** those cookies in the response; otherwise the browser may keep sending them until they expire on their own.

**Two cookies matter:**

1. **Auth cookie** – Default name: `.AspNetCore.Identity.Application`. It holds the signed-in user. While it exists and is valid, `User.Identity.IsAuthenticated` is true.
2. **Session cookie** – Default name: `.AspNetCore.Session`. It holds only a session ID. The real data (e.g. UserId, SessionId) lives on the server and is looked up by that ID.

You will:
- Set both to expire after the same inactivity window (e.g. 1 minute).
- On timeout, logout, or “session invalidated,” clear server-side state and **delete both cookies** with the same options they were set with (path, domain, secure, same-site) so the browser actually removes them.

---

## 2. Server-Side Configuration

### 2.1 Identity application cookie (auth cookie)

In `Program.cs` (or wherever you configure services), use `ConfigureApplicationCookie`:

- **ExpireTimeSpan** – e.g. `TimeSpan.FromMinutes(1)`. The cookie is valid for this long from its last “renewal.”
- **SlidingExpiration = true** – Each request that uses the cookie counts as renewal. So expiry is “1 minute with no requests.”
- Set **LoginPath**, **LogoutPath**, **AccessDeniedPath** as needed.
- Cookie options: **HttpOnly = true** (not readable by JS), **SameSite = Strict**, **SecurePolicy = SameAsRequest** (so it works on HTTP in dev and HTTPS in prod).

Conceptually: the auth ticket inside the cookie has an expiry; the framework rejects it after that. Sliding expiration means every request that uses the cookie extends that expiry. No request for 1 minute → ticket expires → next request is unauthenticated.

### 2.2 Session

Use `AddSession` with:

- **IdleTimeout** – e.g. `TimeSpan.FromMinutes(1)`. If the session is not read or written for this long, the server drops the session data. The cookie may still be sent, but the server will treat it as a new/empty session.
- Session cookie: **HttpOnly = true**, **IsEssential = true** (so it is not blocked by strict consent flows).

Keep **IdleTimeout** and the auth **ExpireTimeSpan** the same so “session expired” and “auth expired” align.

---

## 3. Deleting Cookies Correctly

To remove a cookie, you must send a **Set-Cookie** that has the **same name, path, domain, and secure** as when it was set, with an expiry in the past (or max-age=0). In ASP.NET Core you do this with `Response.Cookies.Delete(cookieName, options)`.

**Always use the same options when deleting:**

- **Path**: `/` (must match how the cookie was set).
- **HttpOnly**: `true`.
- **SameSite**: `SameSiteMode.Strict` (or whatever you use for the app).
- **Secure**: match the current request (e.g. `context.Request.IsHttps`) so in HTTP dev you don’t require Secure, and in HTTPS you do.

If path/domain/secure don’t match, the browser will not delete the cookie and will keep sending it.

**Implement two helpers (same logic in both Account controller and any middleware that clears cookies):**

- **ClearSessionCookie(context)** – `Response.Cookies.Delete(".AspNetCore.Session", options)` with the options above.
- **ClearAuthCookie(context)** – `Response.Cookies.Delete(".AspNetCore.Identity.Application", options)` with the same options.

Use the exact cookie names your framework uses (Identity and session defaults are as above).

---

## 4. When to Clear Cookies and Session

Apply this in four situations.

### 4.1 User lands on Login with “forced logout” query

When the user is sent to the Login page **because** of timeout or invalidation, you pass a query parameter, e.g. `?sessionExpired=true` or `?sessionInvalidated=1`. In the **Login GET** action:

1. Read the query (e.g. `sessionExpired=true` or `sessionInvalidated=1`).
2. If either is present (“forced logout”):
   - If the user is still authenticated, call `SignOutAsync()`.
   - Call `HttpContext.Session.Clear()`.
   - Call your **ClearSessionCookie** and **ClearAuthCookie** helpers so the response tells the browser to remove both cookies.
3. Optionally set TempData messages: e.g. “Your session has expired” for `sessionExpired`, “You were signed out because you logged in elsewhere” for `sessionInvalidated`.
4. Return the Login view.

This way, whenever the client (or another part of the app) redirects to Login with those query params, the very first thing the server does is clean up auth and session and remove the cookies.

### 4.2 Explicit logout

In your **Logout** action (POST):

1. Optionally log/audit the logout.
2. `HttpContext.Session.Clear()`.
3. Call **ClearSessionCookie**.
4. `SignOutAsync()` (so Identity marks the user as signed out and will send an auth-cookie delete; calling ClearAuthCookie as well ensures it).
5. Call **ClearAuthCookie**.
6. Redirect to Login.

Order doesn’t have to be exact as long as both cookies are deleted and SignOut is called.

### 4.3 Single-session invalidation (e.g. “logged in elsewhere”)

If you have middleware that enforces “only one session per user”:

- When you detect that the current request’s session is no longer the “allowed” one (e.g. user logged in on another device):
  1. Call `SignOutAsync()`.
  2. `context.Session.Clear()`.
  3. Call **ClearSessionCookie** and **ClearAuthCookie**.
  4. Redirect to Login with a query like `?sessionInvalidated=1`.

The Login GET (see 4.1) will run again when they hit that URL and clear cookies again if needed; that’s safe and ensures cookies are gone even if the redirect is cached or odd.

### 4.4 Server detects “no session data” (optional but recommended)

On protected pages (e.g. Dashboard, Home when logged in), if you store something in session (e.g. `UserId`) at login:

- If `HttpContext.Session.GetString("UserId")` (or equivalent) is null but the user is still authenticated (auth cookie still valid), treat as “session expired”:
  1. Call `SignOutAsync()` so the auth cookie is cleared in the response.
  2. Redirect to Login, e.g. with TempData “Your session has expired.”

You don’t have to delete the session cookie here if you prefer to do it only when they hit Login with `sessionExpired=true`; the important part is signing out and redirecting so they don’t stay “half logged in.”

---

## 5. Client-Side Timeout (Optional but Recommended)

Server-side: the auth cookie and session both expire after 1 minute of no requests. The user might still have the page open and not make a request until they click something, at which point the server will reject them. To improve UX:

- On pages that are only shown when the user is “in session” (e.g. Dashboard, Home when logged in), add a **client-side script** that:
  - Starts a timer for the same duration as the server (e.g. 1 minute = 60 * 1000 ms).
  - Resets the timer on activity (e.g. `mousemove`, `keypress`, `click`).
  - When the timer fires: redirect to **Login with a query**, e.g. `window.location.href = '/Account/Login?sessionExpired=true'`.

Then the user is sent to Login with `sessionExpired=true`, and your Login GET (4.1) clears both cookies and shows “Your session has expired.”

You can also show a warning (e.g. 30 seconds before) with an alert or modal: “Your session will expire in 30 seconds. Save your work.”

Important: the **real** expiry is still on the server (cookie/session config). The client script only decides **when** to redirect so the user lands on Login and gets the cookie cleanup.

---

## 6. Flow Summary (Implementation Checklist)

1. **Configure** auth cookie: ExpireTimeSpan (e.g. 1 min), SlidingExpiration = true, HttpOnly, SameSite, Secure.
2. **Configure** session: IdleTimeout same as ExpireTimeSpan (e.g. 1 min), session cookie HttpOnly (and IsEssential if needed).
3. **Implement** ClearSessionCookie and ClearAuthCookie using `Response.Cookies.Delete` with Path=/, HttpOnly, SameSite, Secure matching the request.
4. **Login GET:** If query has `sessionExpired=true` or `sessionInvalidated=1`, sign out, clear session, call both clear-cookie helpers, then show Login (and optional TempData messages).
5. **Logout:** Clear session, clear both cookies, SignOutAsync, redirect to Login.
6. **Single-session middleware (if any):** On “not the allowed session,” SignOutAsync, clear session, clear both cookies, redirect to Login?sessionInvalidated=1.
7. **Protected pages (optional):** If session data (e.g. UserId) is null but user is authenticated, SignOutAsync and redirect to Login.
8. **Client script (optional):** On “in session” pages, 1-minute inactivity timer; on expiry redirect to Login?sessionExpired=true; optionally warn 30 seconds before.

---

## 7. Why This Works

- **Same timeout everywhere:** Auth and session both expire after the same inactivity window, so you don’t have “auth valid but session empty” (or the reverse) for long.
- **Explicit cookie delete:** Merely calling `SignOutAsync()` or letting the cookie expire can leave the cookie in the browser until its expiry. Deleting with matching options ensures the browser drops it on the next response.
- **Single “forced logout” entry point:** Redirecting to Login with a query and clearing cookies there means every timeout/invalidation path can rely on one place to remove cookies, so behavior is consistent and you can implement it without looking at the rest of the code once this contract is clear.
