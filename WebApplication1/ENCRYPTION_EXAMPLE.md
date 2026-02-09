# Encryption Implementation Guide

This document shows how encryption is set up in this application, similar to the Register.cshtml.cs pattern.

## Setup Complete ✅

1. **Data Protection Services** - Configured in `Program.cs`
2. **Encryption Service** - Created in `Services/EncryptionService.cs`
3. **Controller Integration** - Prepared in `HomeController.cs`

## How It Works

### 1. Encryption Before Saving (Similar to Credit Card Example)

```csharp
// In your controller or service:
var protector = _dataProtectionProvider.CreateProtector("MySecretKey");
string encryptedComment = protector.Protect(comment);

// Save encrypted value to database
// Example:
// var user = new ApplicationUser()
// {
//     UserName = model.Email,
//     Email = model.Email,
//     CreditCard = protector.Protect(model.CreditCard)  // Encrypt before saving
// };
// await userManager.CreateAsync(user, model.Password);
```

### 2. Decryption When Retrieving

```csharp
// When retrieving from database:
var protector = _dataProtectionProvider.CreateProtector("MySecretKey");
string decryptedComment = protector.Unprotect(encryptedCommentFromDatabase);

// Then HTML encode for safe display
string safeDisplay = WebUtility.HtmlEncode(decryptedComment);
```

## Alternative: Using EncryptionService

For cleaner code, you can inject `EncryptionService`:

```csharp
public class HomeController : Controller
{
    private readonly EncryptionService _encryptionService;

    public HomeController(EncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
    }

    [HttpPost]
    public IActionResult Index(string comment)
    {
        // Encrypt
        string encrypted = _encryptionService.Encrypt(comment);
        
        // Save to database...
        
        // Later, when retrieving:
        // string decrypted = _encryptionService.Decrypt(encryptedFromDatabase);
    }
}
```

## Key Points

- ✅ **Encrypt before saving** - Sensitive data is encrypted at rest
- ✅ **Decrypt when retrieving** - Decrypt before displaying
- ✅ **HTML encode for display** - Always HTML encode decrypted values to prevent XSS
- ✅ **Same secret key** - Use the same "MySecretKey" for both encrypt and decrypt

## Configuration

The encryption keys are stored in: `C:\temp\keys\` (configured in `Program.cs`)

**Important:** Change this path in production and ensure the directory exists and is secured!
