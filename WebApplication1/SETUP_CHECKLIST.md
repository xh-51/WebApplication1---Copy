# Setup Checklist

## ✅ Required Steps (Must Do)

- [ ] **Install Entity Framework Tools**
  ```bash
  dotnet tool install --global dotnet-ef
  ```

- [ ] **Create Database Migration**
  ```bash
  cd WebApplication1
  dotnet ef migrations add InitialCreate
  ```

- [ ] **Create Database**
  ```bash
  dotnet ef database update
  ```

- [ ] **Restore Packages**
  ```bash
  dotnet restore
  ```

- [ ] **Build Project**
  ```bash
  dotnet build
  ```

- [ ] **Run Application**
  ```bash
  dotnet run
  ```

- [ ] **Test Registration**
  - Navigate to: `https://localhost:5001/Account/Register`
  - Create a test account

---

## ⚠️ Optional Steps (Recommended)

- [ ] **Get Google reCaptcha Keys**
  - Visit: https://www.google.com/recaptcha/admin/create
  - Create reCAPTCHA v3 site
  - Add domain: `localhost`
  - Copy Site Key and Secret Key
  - Update `appsettings.json` lines 17-18

- [ ] **Configure Email (For Production)**
  - Currently password reset shows link in browser
  - For production, configure SMTP or email service

---

## 🎯 Quick Test

After setup, test these:

1. ✅ Register new user
2. ✅ Login
3. ✅ View profile on homepage
4. ✅ Change password
5. ✅ Enable 2FA
6. ✅ Test password reset

---

## 📝 Notes

- **reCaptcha**: App works without it, but login won't have bot protection
- **Database**: Uses SQL Server LocalDB (comes with Visual Studio)
- **Encryption Keys**: Auto-created at `C:\temp\keys\`
- **File Uploads**: Auto-created at `wwwroot/uploads/resumes/`

---

## 🚀 You're Ready!

Once you complete the Required Steps, you can start using the application!
