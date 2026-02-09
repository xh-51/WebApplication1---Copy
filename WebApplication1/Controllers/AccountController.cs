using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;
using WebApplication1.Services;
using System.Text.Json;

namespace WebApplication1.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly EncryptionService _encryptionService;
        private readonly AuditLogService _auditLogService;
        private readonly InputValidationService _inputValidationService;
        private readonly PasswordPolicyService _passwordPolicyService;
        private readonly IWebHostEnvironment _environment;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAntiforgery _antiforgery;
        private readonly IEmailSender _emailSender;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            EncryptionService encryptionService,
            AuditLogService auditLogService,
            InputValidationService inputValidationService,
            PasswordPolicyService passwordPolicyService,
            IWebHostEnvironment environment,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IAntiforgery antiforgery,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryptionService = encryptionService;
            _auditLogService = auditLogService;
            _inputValidationService = inputValidationService;
            _passwordPolicyService = passwordPolicyService;
            _environment = environment;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _antiforgery = antiforgery;
            _emailSender = emailSender;
        }

        [HttpGet]
        public IActionResult Register()
        {
            // Pass reCaptcha site key to view
            ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
            return View();
        }

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
                ModelState.AddModelError(string.Empty, "Registration failed. Please check your details and try again. If the problem continues, ensure SQL Server (LocalDB) is running and the app has write access to the uploads folder.");
                return View(model);
            }
        }

        private async Task<IActionResult> RegisterCoreAsync(RegisterViewModel model, string recaptchaToken)
        {
            // ============================================
            // INPUT VALIDATION & SANITIZATION
            // ============================================
            
            // Server-side validation (additional to client-side)
            if (!_inputValidationService.IsValidEmail(model.Email))
            {
                ModelState.AddModelError("Email", "Invalid email address format.");
            }

            if (!_inputValidationService.IsValidNRIC(model.NRIC))
            {
                ModelState.AddModelError("NRIC", "Invalid NRIC format. Must be in format S1234567A");
            }

            if (!_inputValidationService.IsValidGender(model.Gender))
            {
                ModelState.AddModelError("Gender", "Invalid gender selection.");
            }

            if (!_inputValidationService.IsValidDateOfBirth(model.DateOfBirth))
            {
                ModelState.AddModelError("DateOfBirth", "Invalid date of birth. Must be between 13 and 120 years old.");
            }

            // Validate and sanitize text inputs to prevent XSS and SQL Injection
            var firstNameValidation = _inputValidationService.ValidateAndEncodeForDatabase("First Name", model.FirstName);
            if (!firstNameValidation.IsValid)
            {
                ModelState.AddModelError("FirstName", firstNameValidation.ErrorMessage);
            }

            var lastNameValidation = _inputValidationService.ValidateAndEncodeForDatabase("Last Name", model.LastName);
            if (!lastNameValidation.IsValid)
            {
                ModelState.AddModelError("LastName", lastNameValidation.ErrorMessage);
            }

            // WhoAmI allows special characters but still needs sanitization
            var whoAmIValidation = _inputValidationService.ValidateAndEncodeForDatabase("Who Am I", model.WhoAmI ?? "", allowSpecialChars: true);
            if (!whoAmIValidation.IsValid)
            {
                ModelState.AddModelError("WhoAmI", whoAmIValidation.ErrorMessage);
            }

            // Verify reCaptcha v3
            if (!await VerifyRecaptchaAsync(recaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "reCaptcha verification failed. Please try again.");
                ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
                return View(model);
            }

            if (ModelState.IsValid)
            {
                // Check if email already exists (unique requirement)
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(string.Empty, "This email is already used to create an account. Please sign in or use a different email.");
                    ModelState.AddModelError("Email", "This email is already registered.");
                    ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
                    return View(model);
                }

                // Handle file upload for resume
                string? resumeFileName = null;
                string? resumeFilePath = null;

                if (model.Resume != null && model.Resume.Length > 0)
                {
                    // Validate file extension
                    var allowedExtensions = new[] { ".docx", ".pdf" };
                    var fileExtension = Path.GetExtension(model.Resume.FileName).ToLowerInvariant();

                    if (!allowedExtensions.Contains(fileExtension))
                    {
                        ModelState.AddModelError("Resume", "Only .docx and .pdf files are allowed.");
                        return View(model);
                    }

                    // Validate file size (5MB max)
                    var maxFileSize = _configuration.GetValue<long>("FileUpload:MaxFileSize", 5242880);
                    if (model.Resume.Length > maxFileSize)
                    {
                        ModelState.AddModelError("Resume", "File size cannot exceed 5MB.");
                        return View(model);
                    }

                    // Create uploads directory if it doesn't exist (handle null WebRootPath)
                    var webRoot = _environment.WebRootPath;
                    if (string.IsNullOrEmpty(webRoot))
                        webRoot = Path.Combine(_environment.ContentRootPath, "wwwroot");
                    if (!Directory.Exists(webRoot))
                        Directory.CreateDirectory(webRoot);
                    var uploadsPath = Path.Combine(webRoot, "uploads", "resumes");
                    if (!Directory.Exists(uploadsPath))
                        Directory.CreateDirectory(uploadsPath);

                    // Generate unique filename
                    var uniqueFileName = $"{Guid.NewGuid()}{fileExtension}";
                    resumeFileName = model.Resume.FileName;
                    resumeFilePath = Path.Combine(uploadsPath, uniqueFileName);

                    // Save file
                    using (var fileStream = new FileStream(resumeFilePath, FileMode.Create))
                    {
                        await model.Resume.CopyToAsync(fileStream);
                    }

                    resumeFilePath = Path.Combine("uploads", "resumes", uniqueFileName);
                }

                // Encrypt NRIC before saving to database
                // Use CreateProtector method to generate the secret instance
                // Use Protect method to encrypt
                string encryptedNRIC = _encryptionService.Encrypt(model.NRIC);

                // ============================================
                // ENCODE INPUTS BEFORE SAVING TO DATABASE
                // Prevents XSS attacks - all text fields are HTML encoded
                // ============================================
                
                // Create user object with sanitized and encoded inputs
                // SQL Injection is prevented by Entity Framework Core (parameterized queries)
                var user = new ApplicationUser
                {
                    UserName = model.Email, // Use email as username
                    Email = model.Email, // Email is validated separately
                    FirstName = _inputValidationService.HtmlEncode(firstNameValidation.SanitizedValue), // HTML encoded
                    LastName = _inputValidationService.HtmlEncode(lastNameValidation.SanitizedValue), // HTML encoded
                    Gender = model.Gender, // Validated from dropdown
                    NRIC = encryptedNRIC, // Encrypted (not just encoded)
                    DateOfBirth = model.DateOfBirth, // Validated date
                    ResumeFileName = resumeFileName != null ? _inputValidationService.HtmlEncode(resumeFileName) : null, // HTML encoded
                    ResumeFilePath = resumeFilePath, // Path is safe (generated by system)
                    WhoAmI = !string.IsNullOrEmpty(model.WhoAmI) ? _inputValidationService.HtmlEncode(whoAmIValidation.SanitizedValue) : null, // HTML encoded
                    EmailConfirmed = true // Set to false if email confirmation is required
                };

                // Create user with password
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Store session ID for multiple login detection
                    HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);
                    HttpContext.Session.SetString("UserId", user.Id);

                    // Audit log: Registration
                    await _auditLogService.LogActivityAsync(
                        user.Id,
                        user.Email ?? "",
                        "Register",
                        "User successfully registered"
                    );

                    // Automatically sign in the user after registration
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Dashboard");
                }

                // Add errors to ModelState
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Login()
        {
            // Pass reCaptcha site key to view
            ViewData["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"] ?? "";
            var sessionExpired = Request.Query["sessionExpired"].FirstOrDefault() == "true";
            var sessionInvalidated = Request.Query["sessionInvalidated"].FirstOrDefault() == "1";
            var forcedLogout = sessionExpired || sessionInvalidated;

            // Prevent query params from appearing as validation errors in the summary
            ModelState.Remove("sessionExpired");
            ModelState.Remove("sessionInvalidated");

            if (forcedLogout)
            {
                // Always sign out and clear session when we know this is a timeout/forced logout
                if (User.Identity?.IsAuthenticated == true)
                    await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                ClearSessionCookie(HttpContext);
                ClearAuthCookie(HttpContext);
            }

            if (sessionExpired)
            {
                TempData["SessionExpired"] = "Your session has expired. Please login again.";
            }

            if (sessionInvalidated)
            {
                TempData["SessionInvalidated"] = "You have been signed out because you logged in from another device or browser.";
            }
            
            return View();
        }

        /// <summary>
        /// Removes the ASP.NET Core session cookie so the session is fully abandoned (e.g. after forced logout).
        /// </summary>
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

        /// <summary>
        /// Ensures the Identity auth cookie is removed (e.g. after forced logout or timeout redirect).
        /// </summary>
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, bool rememberMe, string recaptchaToken)
        {
            // Verify reCaptcha v3
            if (!await VerifyRecaptchaAsync(recaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "reCaptcha verification failed. Please try again.");
                await _auditLogService.LogActivityAsync("", email, "Login Failed", "reCaptcha verification failed");
                return View();
            }

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError(string.Empty, "Email and password are required.");
                return View();
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Your email or password is wrong. Please try again later.");
                await _auditLogService.LogActivityAsync("", email, "Login Failed", "User not found");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(user, password, rememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // Check if 2FA is required
                var is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
                if (is2FAEnabled)
                {
                    // Sign out and redirect to 2FA verification
                    await _signInManager.SignOutAsync();
                    // Store user temporarily for 2FA (Identity handles this)
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Verify2FA", new { rememberMe = rememberMe });
                }

                // Store session ID (used to enforce single session: only latest login is valid)
                HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);
                HttpContext.Session.SetString("UserId", user.Id);

                // Audit log first so single-session middleware allows this session (even when redirecting to ChangePassword)
                await _auditLogService.LogActivityAsync(
                    user.Id,
                    user.Email ?? "",
                    "Login",
                    "User successfully logged in"
                );

                // Check password expiry
                var (mustChange, message) = _passwordPolicyService.MustChangePassword(user);
                if (mustChange)
                {
                    TempData["PasswordExpired"] = message;
                    return RedirectToAction("ChangePassword");
                }

                return RedirectToAction("Index", "Dashboard");
            }

            if (result.RequiresTwoFactor)
            {
                // This handles 2FA requirement automatically
                return RedirectToAction("Verify2FA", new { rememberMe = rememberMe });
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Account locked out due to 3 failed login attempts. Please try again in 1 minute.");
                await _auditLogService.LogActivityAsync(user.Id, user.Email ?? "", "Account Locked", "Account locked after 3 failed attempts");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Your email or password is wrong. Please try again later.");
                await _auditLogService.LogActivityAsync(user.Id, user.Email ?? "", "Login Failed", "Invalid credentials");
            }

            return View();
        }

        private async Task<bool> VerifyRecaptchaAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];
            if (string.IsNullOrEmpty(secretKey))
                return true;
            // Skip reCAPTCHA in Development to avoid connection/timeout issues during registration
            if (_environment.IsDevelopment())
                return true;

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                var response = await client.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}",
                    null
                );

                var jsonResponse = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<JsonElement>(jsonResponse);

                return result.GetProperty("success").GetBoolean() && 
                       result.GetProperty("score").GetDouble() >= 0.5; // Score threshold
            }
            catch
            {
                return false;
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var userEmail = User.Identity?.Name ?? "";

            // Audit log: Logout
            if (!string.IsNullOrEmpty(userId))
            {
                await _auditLogService.LogActivityAsync(
                    userId,
                    userEmail,
                    "Logout",
                    "User logged out"
                );
            }

            // Clear session, session cookie, and auth cookie
            HttpContext.Session.Clear();
            ClearSessionCookie(HttpContext);
            await _signInManager.SignOutAsync();
            ClearAuthCookie(HttpContext);

            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            // Redirect to Error controller with 403 status
            return RedirectToAction("HttpStatusCodeHandler", "Error", new { statusCode = 403 });
        }

        // ============================================
        // PASSWORD MANAGEMENT
        // ============================================

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Check if password must be changed (expired - max age)
            var (mustChange, message) = _passwordPolicyService.MustChangePassword(user);
            if (mustChange)
            {
                TempData["PasswordExpired"] = message;
                SetPasswordPolicyViewBag();
                return View();
            }

            // If not expired, enforce minimum age: don't allow into change password page until 1 minute since last change
            var (canChange, minAgeError) = _passwordPolicyService.CanChangePassword(user);
            if (!canChange)
            {
                TempData["PasswordChangeNotAllowed"] = minAgeError;
                return RedirectToAction("Index", "Dashboard");
            }

            if (!string.IsNullOrEmpty(message))
            {
                TempData["PasswordWarning"] = message;
            }

            SetPasswordPolicyViewBag();
            return View();
        }

        private void SetPasswordPolicyViewBag()
        {
            var min = _passwordPolicyService.MinAgeMinutes;
            var max = _passwordPolicyService.MaxAgeMinutes;
            var history = _passwordPolicyService.MaxHistoryCount;
            ViewBag.MinAgeMinutes = min;
            ViewBag.MaxAgeMinutes = max;
            ViewBag.MaxHistory = history;
            ViewBag.MinAgeText = min == 1 ? "1 minute" : $"{min} minutes";
            ViewBag.MaxAgeText = max < 60 ? $"{max} minutes" : max < 24 * 60 ? $"{max / 60} hours" : $"{max / (24 * 60)} days";
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                SetPasswordPolicyViewBag();
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Check minimum password age
            var (canChange, errorMessage) = _passwordPolicyService.CanChangePassword(user);
            if (!canChange)
            {
                ModelState.AddModelError(string.Empty, errorMessage);
                SetPasswordPolicyViewBag();
                return View(model);
            }

            // Check password history (prevent reuse of last 2 passwords)
            var (canUse, historyError) = await _passwordPolicyService.CanUsePassword(user, model.NewPassword);
            if (!canUse)
            {
                ModelState.AddModelError("NewPassword", historyError);
                SetPasswordPolicyViewBag();
                return View(model);
            }

            // Verify current password
            var verifyResult = await _userManager.CheckPasswordAsync(user, model.CurrentPassword);
            if (!verifyResult)
            {
                ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
                SetPasswordPolicyViewBag();
                return View(model);
            }

            // Save current password hash to history before changing (for "cannot reuse last 2" check)
            await _passwordPolicyService.AddCurrentPasswordToHistory(user);

            // Change password
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                // Update password change date
                await _passwordPolicyService.UpdatePasswordChangeDate(user);

                // Audit log
                await _auditLogService.LogActivityAsync(
                    user.Id,
                    user.Email ?? "",
                    "Password Changed",
                    "User successfully changed password"
                );

                TempData["SuccessMessage"] = "Your password has been changed successfully.";
                return RedirectToAction("Index", "Dashboard");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            SetPasswordPolicyViewBag();
            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);

            // Same confirmation for existing and non-existing (no user enumeration)
            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email }, protocol: Request.Scheme);

                try
                {
                    await _emailSender.SendEmailAsync(
                        user.Email!,
                        "Reset your Ace Job Agency password",
                        $"Please reset your password by clicking <a href=\"{callbackUrl}\">this secure link</a>. The link will expire after a short time.");
                }
                catch (Exception)
                {
                    // Logged in EmailSender; still show confirmation (no user enumeration)
                }

                await _auditLogService.LogActivityAsync(
                    user.Id,
                    user.Email ?? "",
                    "Password Reset Requested",
                    "User requested password reset");
            }

            return View("ForgotPasswordConfirmation");
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string? email, string? token)
        {
            if (email == null || token == null)
                return RedirectToAction("Login");

            var model = new ResetPasswordViewModel { Email = email, Token = token };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return RedirectToAction("ResetPasswordConfirmation");
            }

            // Password history: cannot reuse last N passwords
            var (canUse, historyError) = await _passwordPolicyService.CanUsePassword(user, model.Password);
            if (!canUse)
            {
                ModelState.AddModelError("Password", historyError);
                return View(model);
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (result.Succeeded)
            {
                await _passwordPolicyService.UpdatePasswordChangeDate(user);

                await _auditLogService.LogActivityAsync(
                    user.Id,
                    user.Email ?? "",
                    "Password Reset",
                    "User successfully reset password");

                return RedirectToAction("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        // ============================================
        // TWO-FACTOR AUTHENTICATION (2FA)
        // ============================================

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Enable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Check if 2FA is already enabled
            var is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (is2FAEnabled)
            {
                TempData["InfoMessage"] = "Two-factor authentication is already enabled.";
                return RedirectToAction("Index", "Dashboard");
            }

            // Generate authenticator key
            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(authenticatorKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            ViewBag.AuthenticatorKey = authenticatorKey;
            ViewBag.QrCodeUri = $"otpauth://totp/AceJobAgency:{user.Email}?secret={authenticatorKey}&issuer=AceJobAgency";

            return View();
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Enable2FA(string verificationCode)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Verify the code
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, 
                _userManager.Options.Tokens.AuthenticatorTokenProvider, 
                verificationCode
            );

            if (!isValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid verification code.");
                var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
                ViewBag.AuthenticatorKey = authenticatorKey;
                ViewBag.QrCodeUri = $"otpauth://totp/AceJobAgency:{user.Email}?secret={authenticatorKey}&issuer=AceJobAgency";
                return View();
            }

            // Enable 2FA
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            // Audit log
            await _auditLogService.LogActivityAsync(
                user.Id,
                user.Email ?? "",
                "2FA Enabled",
                "User enabled two-factor authentication"
            );

            TempData["SuccessMessage"] = "Two-factor authentication has been enabled successfully.";
            return RedirectToAction("Index", "Dashboard");
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);

            // Audit log
            await _auditLogService.LogActivityAsync(
                user.Id,
                user.Email ?? "",
                "2FA Disabled",
                "User disabled two-factor authentication"
            );

            TempData["SuccessMessage"] = "Two-factor authentication has been disabled.";
            return RedirectToAction("Index", "Dashboard");
        }

        [HttpGet]
        public IActionResult Verify2FA(bool rememberMe = false)
        {
            ViewBag.RememberMe = rememberMe;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2FA(string verificationCode, bool rememberMe)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(verificationCode, rememberMe, rememberMe);

            if (result.Succeeded)
            {
                // Store session ID
                HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);
                HttpContext.Session.SetString("UserId", user.Id);

                // Audit log first so single-session middleware allows this session (even when redirecting to ChangePassword)
                await _auditLogService.LogActivityAsync(
                    user.Id,
                    user.Email ?? "",
                    "2FA Login",
                    "User successfully logged in with 2FA"
                );

                // Check password expiry
                var (mustChange, message) = _passwordPolicyService.MustChangePassword(user);
                if (mustChange)
                {
                    TempData["PasswordExpired"] = message;
                    return RedirectToAction("ChangePassword");
                }

                return RedirectToAction("Index", "Dashboard");
            }

            ModelState.AddModelError(string.Empty, "Invalid verification code.");
            ViewBag.RememberMe = rememberMe;
            return View();
        }
    }
}
