# Ace Job Agency - Setup Guide

## Security Features Implemented ✅

1. **NRIC Encryption** - NRIC is encrypted using DataProtectionProvider before saving to database
2. **Email Uniqueness** - Email addresses must be unique (enforced at database and application level)
3. **Secure Password Requirements**:
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character
4. **File Upload Security**:
   - Only .docx and .pdf files allowed
   - Maximum file size: 5MB
   - Files stored securely in wwwroot/uploads/resumes/
5. **Account Lockout** - 5 failed login attempts locks account for 5 minutes
6. **HTTPS Enforcement** - HTTPS redirection enabled
7. **Anti-Forgery Tokens** - CSRF protection on all forms
8. **Input Validation** - Server-side and client-side validation

## Database Setup

### Step 1: Install Entity Framework Tools (if not already installed)
```bash
dotnet tool install --global dotnet-ef
```

### Step 2: Create Initial Migration
```bash
cd WebApplication1
dotnet ef migrations add InitialCreate
```

### Step 3: Update Database
```bash
dotnet ef database update
```

This will create the database with all Identity tables and your ApplicationUser table.

## Configuration

### Connection String
Update the connection string in `appsettings.json` if needed:
```json
"ConnectionStrings": {
  "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=AceJobAgencyDB;Trusted_Connection=True;MultipleActiveResultSets=true"
}
```

### Encryption Keys
Encryption keys are stored in: `C:\temp\keys\`

**Important for Production:**
- Change the key storage location to a secure path
- Consider using Azure Key Vault or similar for production
- Ensure the directory has proper permissions

## Running the Application

1. Restore packages:
```bash
dotnet restore
```

2. Build the application:
```bash
dotnet build
```

3. Run the application:
```bash
dotnet run
```

4. Navigate to: `https://localhost:5001` (or the port shown in console)

## Registration Form Fields

All required fields are implemented:
- ✅ First Name
- ✅ Last Name
- ✅ Gender (Male/Female/Other)
- ✅ NRIC (Encrypted before saving)
- ✅ Email Address (Must be unique)
- ✅ Password (Secure requirements enforced)
- ✅ Confirm Password
- ✅ Date of Birth
- ✅ Resume (.docx or .pdf file upload)
- ✅ Who Am I (allows all special characters)

## Homepage Features

- Displays user profile information after login
- Shows decrypted NRIC (decrypted on-the-fly for display only)
- Download link for uploaded resume
- Secure logout functionality

## Testing

1. Register a new user with all required fields
2. Login with registered email
3. View profile information on homepage
4. Verify NRIC is encrypted in database but displayed correctly on homepage
5. Test file upload with .docx and .pdf files
6. Test validation by submitting invalid data

## Security Notes

- NRIC is **never** stored in plain text in the database
- Passwords are hashed using ASP.NET Core Identity's secure hashing
- File uploads are validated for type and size
- All user input is validated and sanitized
- Session cookies are secure and HTTP-only

## Troubleshooting

### Database Connection Issues
- Ensure SQL Server LocalDB is installed
- Check connection string in appsettings.json
- Verify database was created: `dotnet ef database update`

### File Upload Issues
- Ensure `wwwroot/uploads/resumes/` directory exists
- Check file size (max 5MB)
- Verify file extension is .docx or .pdf

### Encryption Issues
- Ensure `C:\temp\keys\` directory exists and is accessible
- Check that the same "MySecretKey" is used for encrypt/decrypt
