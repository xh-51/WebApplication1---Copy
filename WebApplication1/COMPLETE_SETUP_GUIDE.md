# Complete Setup Guide - Step by Step

## Prerequisites

Before you start, make sure you have:
- ✅ .NET 8.0 SDK installed
- ✅ SQL Server LocalDB installed (comes with Visual Studio)
- ✅ Visual Studio 2022 or VS Code (optional, but recommended)

---

## Step 1: Get Google reCaptcha API Keys (5 minutes)

### Option A: For Testing/Demo (Recommended for now)
**You can skip this step for now** - The application will work without reCaptcha keys, but login won't have bot protection.

### Option B: Get Real Keys (For Production/Demo)

1. **Go to Google reCaptcha Admin Console**:
   - Visit: https://www.google.com/recaptcha/admin/create

2. **Create a new site**:
   - **Label**: Ace Job Agency (or any name)
   - **reCaptcha type**: Select **reCAPTCHA v3**
   - **Domains**: 
     - For local testing: `localhost`
     - For production: Your domain (e.g., `acejobagency.com`)
   - Accept terms and click **Submit**

3. **Copy your keys**:
   - **Site Key** (public key) - This goes in your frontend
   - **Secret Key** (private key) - This goes in your backend

4. **Update `appsettings.json`**:
   ```json
   "GoogleReCaptcha": {
     "SiteKey": "YOUR_SITE_KEY_HERE",
     "SecretKey": "YOUR_SECRET_KEY_HERE"
   }
   ```

**Note**: For localhost testing, reCaptcha v3 works but may show low scores. This is normal.

---

## Step 2: Database Setup

### Install Entity Framework Tools (if not already installed)

Open PowerShell or Command Prompt and run:

```bash
dotnet tool install --global dotnet-ef
```

If already installed, update it:
```bash
dotnet tool update --global dotnet-ef
```

### Create Database Migration

1. **Open terminal in project folder**:
   ```bash
   cd "C:\Users\sgong\Downloads\WebApplication1 - Copy\WebApplication1"
   ```

2. **Create migration**:
   ```bash
   dotnet ef migrations add InitialCreate
   ```

   This creates the database schema with all Identity tables.

3. **Create the database**:
   ```bash
   dotnet ef database update
   ```

   This creates the database `AceJobAgencyDB` in SQL Server LocalDB.

**Expected Output**: 
- Database created successfully
- All Identity tables created (AspNetUsers, AspNetRoles, etc.)
- AuditLogs table created

---

## Step 3: Verify Configuration

### Check `appsettings.json`

Make sure these settings are correct:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=AceJobAgencyDB;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "GoogleReCaptcha": {
    "SiteKey": "YOUR_RECAPTCHA_SITE_KEY_HERE",  // Optional for now
    "SecretKey": "YOUR_RECAPTCHA_SECRET_KEY_HERE"  // Optional for now
  },
  "PasswordPolicy": {
    "MinAgeMinutes": 5,
    "MaxAgeMinutes": 129600,
    "MaxHistory": 2
  }
}
```

**Note**: 
- Connection string is already set for LocalDB
- reCaptcha keys are optional (app works without them)
- Password policy settings are already configured

---

## Step 4: Restore and Build

### Restore NuGet Packages

```bash
cd "C:\Users\sgong\Downloads\WebApplication1 - Copy\WebApplication1"
dotnet restore
```

### Build the Project

```bash
dotnet build
```

**Expected Output**: Build succeeded with no errors

---

## Step 5: Create Required Directories

The application will auto-create these, but you can create them manually:

1. **Encryption Keys Directory**:
   - Location: `C:\temp\keys\`
   - **Note**: The app creates this automatically, but ensure you have write permissions

2. **File Upload Directory**:
   - Location: `wwwroot/uploads/resumes/`
   - **Note**: The app creates this automatically when you upload a file

---

## Step 6: Run the Application

### Option A: Using Command Line

```bash
cd "C:\Users\sgong\Downloads\WebApplication1 - Copy\WebApplication1"
dotnet run
```

### Option B: Using Visual Studio

1. Open `WebApplication1.sln` in Visual Studio
2. Press `F5` or click "Run"

### Expected Output

You should see:
```
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:5001
      Now listening on: http://localhost:5000
```

### Access the Application

- **HTTPS**: https://localhost:5001
- **HTTP**: http://localhost:5000

**Note**: You may need to accept the SSL certificate warning (this is normal for localhost)

---

## Step 7: Test the Application

### 1. Test Registration
- Navigate to: `https://localhost:5001/Account/Register`
- Fill in all fields
- Submit form
- Should redirect to homepage

### 2. Test Login
- Navigate to: `https://localhost:5001/Account/Login`
- Enter email and password
- Should login successfully

### 3. Test Homepage
- After login, should see your profile information
- NRIC should be displayed (decrypted)

---

## Optional: Email Configuration (For Password Reset)

Currently, password reset shows the link in the browser. For production, you'd need to configure email:

### Option 1: Use SMTP (Simple)

Add to `appsettings.json`:
```json
"EmailSettings": {
  "SmtpServer": "smtp.gmail.com",
  "SmtpPort": 587,
  "SmtpUsername": "your-email@gmail.com",
  "SmtpPassword": "your-app-password",
  "FromEmail": "your-email@gmail.com",
  "FromName": "Ace Job Agency"
}
```

### Option 2: Use SendGrid, Mailgun, etc. (Recommended for production)

For now, the demo shows the reset link in the browser, which is fine for testing.

---

## Troubleshooting

### Issue: "Cannot connect to database"

**Solution**:
1. Check if SQL Server LocalDB is installed
2. Try: `sqllocaldb start MSSQLLocalDB`
3. Verify connection string in `appsettings.json`

### Issue: "Migration failed"

**Solution**:
1. Delete existing migrations: `dotnet ef migrations remove`
2. Delete database if exists
3. Run `dotnet ef migrations add InitialCreate` again
4. Run `dotnet ef database update`

### Issue: "reCaptcha not working"

**Solution**:
- For localhost testing, reCaptcha may show low scores (this is normal)
- You can temporarily disable reCaptcha by leaving keys empty
- The app will skip verification if keys are not set

### Issue: "Encryption keys directory error"

**Solution**:
- Ensure `C:\temp\keys\` directory exists
- Check write permissions
- Or change path in `Program.cs` line 22

### Issue: "Port already in use"

**Solution**:
- Change port in `launchSettings.json` (if exists)
- Or use: `dotnet run --urls "https://localhost:5002"`

---

## Quick Setup Checklist

- [ ] Get reCaptcha keys (optional for now)
- [ ] Update `appsettings.json` with reCaptcha keys (if obtained)
- [ ] Install Entity Framework Tools: `dotnet tool install --global dotnet-ef`
- [ ] Create migration: `dotnet ef migrations add InitialCreate`
- [ ] Create database: `dotnet ef database update`
- [ ] Restore packages: `dotnet restore`
- [ ] Build project: `dotnet build`
- [ ] Run application: `dotnet run`
- [ ] Test registration: Navigate to `/Account/Register`
- [ ] Test login: Navigate to `/Account/Login`

---

## What Works Without Configuration

✅ **Registration** - Works immediately
✅ **Login** - Works (reCaptcha optional)
✅ **Password Management** - Works immediately
✅ **2FA** - Works immediately
✅ **All Security Features** - Work immediately

## What Needs Configuration

⚠️ **reCaptcha** - Optional (app works without it, but login won't have bot protection)
⚠️ **Email** - Optional (password reset shows link in browser for demo)

---

## Ready to Go!

Once you complete Steps 1-6, your application is ready to run! 

**Minimum Setup** (if you skip reCaptcha):
1. ✅ Install EF Tools
2. ✅ Create migration
3. ✅ Update database
4. ✅ Run application

That's it! Everything else works out of the box.
