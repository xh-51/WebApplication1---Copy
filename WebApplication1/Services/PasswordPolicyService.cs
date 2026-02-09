using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    /// <summary>
    /// Service for enforcing password policies:
    /// - Password history (max 2 previous passwords - cannot reuse)
    /// - Minimum password age (cannot change within x minutes)
    /// - Maximum password age (must change after x minutes)
    /// </summary>
    public class PasswordPolicyService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private readonly IConfiguration _configuration;

        // Password policy settings (in minutes)
        private readonly int MinPasswordAgeMinutes = 5; // Cannot change password within 5 minutes
        private readonly int MaxPasswordAgeMinutes = 90; // Must change password after 90 days (90 * 24 * 60 minutes)
        private readonly int MaxPasswordHistory = 2; // Remember last 2 passwords

        public PasswordPolicyService(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext dbContext,
            IPasswordHasher<ApplicationUser> passwordHasher,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _dbContext = dbContext;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
            
            // Get from configuration if available
            MinPasswordAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinAgeMinutes", 5);
            MaxPasswordAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MaxAgeMinutes", 90 * 24 * 60); // 90 days default
            MaxPasswordHistory = _configuration.GetValue<int>("PasswordPolicy:MaxHistory", 2);
        }

        /// <summary>Minimum age in minutes before password can be changed again. For display on Change Password page.</summary>
        public int MinAgeMinutes => MinPasswordAgeMinutes;
        /// <summary>Maximum age in minutes after which password expires. For display on Change Password page.</summary>
        public int MaxAgeMinutes => MaxPasswordAgeMinutes;
        /// <summary>Number of previous passwords that cannot be reused. For display on Change Password page.</summary>
        public int MaxHistoryCount => MaxPasswordHistory;

        /// <summary>
        /// Check if user can change password (minimum age check)
        /// </summary>
        public (bool CanChange, string ErrorMessage) CanChangePassword(ApplicationUser user)
        {
            if (user.LastPasswordChangeDate == null)
            {
                return (true, ""); // First time, can change
            }

            var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
            var minAge = TimeSpan.FromMinutes(MinPasswordAgeMinutes);

            if (timeSinceLastChange < minAge)
            {
                var remainingMinutes = (int)(minAge - timeSinceLastChange).TotalMinutes;
                return (false, $"You cannot change your password within {MinPasswordAgeMinutes} minutes of the last change. Please try again in {remainingMinutes} minute(s).");
            }

            return (true, "");
        }

        /// <summary>
        /// Check if password must be changed (maximum age check)
        /// </summary>
        public (bool MustChange, string Message) MustChangePassword(ApplicationUser user)
        {
            if (user.LastPasswordChangeDate == null)
            {
                return (false, ""); // First time, not required yet
            }

            var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
            var maxAge = TimeSpan.FromMinutes(MaxPasswordAgeMinutes);

            if (timeSinceLastChange >= maxAge)
            {
                if (MaxPasswordAgeMinutes < 24 * 60) // Expiry is in minutes (e.g. 10 minutes)
                    return (true, "Your password has expired. You must change your password.");
                var daysOverdue = (int)(timeSinceLastChange - maxAge).TotalDays;
                return (true, $"Your password is {daysOverdue} day(s) overdue. You must change your password.");
            }

            // Warn if close to expiry
            var timeUntilExpiry = maxAge - timeSinceLastChange;
            if (MaxPasswordAgeMinutes < 24 * 60 && timeUntilExpiry.TotalMinutes <= 2 && timeUntilExpiry.TotalMinutes > 0)
            {
                return (false, $"Your password will expire in {(int)timeUntilExpiry.TotalMinutes} minute(s). Please change it soon.");
            }
            var daysUntilExpiry = (int)timeUntilExpiry.TotalDays;
            if (daysUntilExpiry <= 7 && daysUntilExpiry > 0)
            {
                return (false, $"Your password will expire in {daysUntilExpiry} day(s). Please change it soon.");
            }

            return (false, "");
        }

        /// <summary>
        /// Check if the new password was used in the last 2 passwords (password history). Returns (false, error) if reuse.
        /// If UserPasswordHistories table is missing, allows the password (no crash).
        /// </summary>
        public async Task<(bool CanUse, string ErrorMessage)> CanUsePassword(ApplicationUser user, string newPassword)
        {
            try
            {
                var recentHashes = await _dbContext.UserPasswordHistories
                    .Where(h => h.UserId == user.Id)
                    .OrderByDescending(h => h.CreatedAtUtc)
                    .Take(MaxPasswordHistory)
                    .Select(h => h.PasswordHash)
                    .ToListAsync();

                foreach (var hash in recentHashes)
                {
                    var result = _passwordHasher.VerifyHashedPassword(user, hash, newPassword);
                    if (result == PasswordVerificationResult.Success || result == PasswordVerificationResult.SuccessRehashNeeded)
                    {
                        return (false, "You cannot reuse any of your last 2 passwords. Please choose a different password.");
                    }
                }
            }
            catch (Microsoft.Data.SqlClient.SqlException)
            {
                // Table may not exist yet; allow password so Reset/Change Password still works
            }

            return (true, "");
        }

        /// <summary>
        /// Save the user's current password hash to history before changing it. Call this before ChangePasswordAsync.
        /// Keeps only the last MaxPasswordHistory entries per user. No-op if UserPasswordHistories table is missing.
        /// </summary>
        public async Task AddCurrentPasswordToHistory(ApplicationUser user)
        {
            if (string.IsNullOrEmpty(user.PasswordHash))
                return;

            try
            {
                _dbContext.UserPasswordHistories.Add(new UserPasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash,
                    CreatedAtUtc = DateTime.UtcNow
                });
                await _dbContext.SaveChangesAsync();

                // Keep only last MaxPasswordHistory per user
                var toRemove = await _dbContext.UserPasswordHistories
                    .Where(h => h.UserId == user.Id)
                    .OrderByDescending(h => h.CreatedAtUtc)
                    .Skip(MaxPasswordHistory)
                    .ToListAsync();
                if (toRemove.Count > 0)
                {
                    _dbContext.UserPasswordHistories.RemoveRange(toRemove);
                    await _dbContext.SaveChangesAsync();
                }
            }
            catch (Microsoft.Data.SqlClient.SqlException)
            {
                // Table may not exist; skip so Change Password still works
            }
        }

        /// <summary>
        /// Update password change tracking
        /// </summary>
        public async Task UpdatePasswordChangeDate(ApplicationUser user)
        {
            user.LastPasswordChangeDate = DateTime.UtcNow;
            user.PasswordHistoryCount = Math.Min(user.PasswordHistoryCount + 1, MaxPasswordHistory);
            await _userManager.UpdateAsync(user);
        }

        /// <summary>
        /// Get password policy information
        /// </summary>
        public (int MinAgeMinutes, int MaxAgeDays, int MaxHistory) GetPolicyInfo()
        {
            return (MinPasswordAgeMinutes, MaxPasswordAgeMinutes / (24 * 60), MaxPasswordHistory);
        }
    }
}
