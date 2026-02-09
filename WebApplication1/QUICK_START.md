# Quick Start - Get Running in 5 Minutes

## Minimum Setup (Skip reCaptcha for now)

### 1. Install EF Tools (One-time)
```bash
dotnet tool install --global dotnet-ef
```

### 2. Create Database
```bash
cd WebApplication1
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### 3. Run Application
```bash
dotnet restore
dotnet build
dotnet run
```

### 4. Open Browser
Navigate to: `https://localhost:5001`

**Done!** ✅

---

## Optional: Add reCaptcha (5 minutes)

1. Go to: https://www.google.com/recaptcha/admin/create
2. Create reCAPTCHA v3 site
3. Add domain: `localhost`
4. Copy Site Key and Secret Key
5. Update `appsettings.json`:
   ```json
   "GoogleReCaptcha": {
     "SiteKey": "paste-site-key-here",
     "SecretKey": "paste-secret-key-here"
   }
   ```

---

## That's It!

The application works without reCaptcha keys - you just won't have bot protection on login. Everything else works immediately!
