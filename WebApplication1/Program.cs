using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebApplication1.Data;
using WebApplication1.Models;
using WebApplication1.Services;

var builder = WebApplication.CreateBuilder(args);

// Allow larger request body (prevents Kestrel from aborting connection on registration with file upload)
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Limits.MaxRequestBodySize = 50 * 1024 * 1024; // 50 MB (avoid reset on large registration form)
});

// Add services to the container.
builder.Services.AddControllersWithViews();

// Allow larger form/multipart request body (e.g. resume upload) to avoid connection reset
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 10 * 1024 * 1024; // 10 MB
    options.ValueLengthLimit = int.MaxValue;
    options.MultipartHeadersLengthLimit = int.MaxValue;
});

// Add HttpClient for reCaptcha verification
builder.Services.AddHttpClient();

// Add Data Protection services for encryption/decryption
// This enables encryption of sensitive data before saving to database
// IMPORTANT: Ensure the keys directory exists before running the application
// For production, use a secure location and consider using Azure Key Vault or similar
var keysDirectory = new System.IO.DirectoryInfo(@"C:\temp\keys\");
if (!keysDirectory.Exists)
{
    keysDirectory.Create();
}

builder.Services.AddDataProtection()
    .SetApplicationName("WebApplication1")
    .PersistKeysToFileSystem(keysDirectory);

// Register encryption service for dependency injection
builder.Services.AddScoped<EncryptionService>();

// Register input validation service
builder.Services.AddScoped<InputValidationService>();

// Add HttpContextAccessor for audit logging
builder.Services.AddHttpContextAccessor();

// Register audit log service
builder.Services.AddScoped<AuditLogService>();

// Register password policy service
builder.Services.AddScoped<PasswordPolicyService>();

// Add Entity Framework and Identity (retry on transient failures to avoid connection reset)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions => sqlOptions.EnableRetryOnFailure(maxRetryCount: 3, maxRetryDelay: TimeSpan.FromSeconds(5), errorNumbersToAdd: null)));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings - Min 12 chars with complexity
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12; // Changed to 12 characters minimum
    options.Password.RequiredUniqueChars = 1;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false; // Set to true in production

    // Lockout settings - 3 failed attempts, auto-recovery after 5 minutes
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Auto-recovery after 5 minutes
    options.Lockout.MaxFailedAccessAttempts = 3; // Changed to 3 attempts
    options.Lockout.AllowedForNewUsers = true;

    // Two-Factor Authentication settings
    options.Tokens.AuthenticatorTokenProvider = "Authenticator";
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddTokenProvider<Microsoft.AspNetCore.Identity.AuthenticatorTokenProvider<ApplicationUser>>("Authenticator");

// Configure cookie settings with session timeout
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20); // Session timeout: 20 minutes
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Add session support for tracking multiple logins
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Create or update database and tables when in Development (so Login/Register work)
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try { db.Database.Migrate(); } catch { /* e.g. LocalDB not running */ }
}

// Catch any unhandled exception and return 500 HTML so connection is never reset
app.Use(async (context, next) =>
{
    try
    {
        await next(context);
    }
    catch (Exception ex)
    {
        // Log so you can see the real error in the terminal when running: dotnet run
        Console.WriteLine("[ERROR] " + ex.ToString());
        if (context.Response.HasStarted) return;
        try
        {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(
                "<!DOCTYPE html><html><head><meta charset='utf-8'/><title>Error</title></head><body>" +
                "<h1>Something went wrong</h1><p>Registration or your request could not be completed. Check the app console for details.</p>" +
                "<p>Common fixes: (1) Start SQL Server LocalDB: <code>sqllocaldb start mssqllocaldb</code> (2) Run the app from terminal: <code>dotnet run</code> and try again.</p>" +
                "<p><a href='/Account/Register'>Back to Register</a> | <a href='/'>Home</a></p></body></html>");
        }
        catch { /* if we can't write response, connection may reset */ }
    }
});

// Use one exception handler so we always return a response (avoids connection reset from re-execute)
// Do NOT use UseDeveloperExceptionPage here - its re-execute can cause ERR_CONNECTION_RESET
if (!app.Environment.IsDevelopment())
{
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}
else
{
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
}

// In Development, skip HTTPS redirect so http://localhost:5000 works (avoids ERR_CONNECTION_REFUSED)
if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();
app.UseStaticFiles();

// Session must be before Routing
app.UseSession();

app.UseRouting();

// Authentication and Authorization must be in this order
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
