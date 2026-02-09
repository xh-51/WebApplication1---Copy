using WebApplication1.Data;
using WebApplication1.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Services
{
    public class AuditLogService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditLogService(ApplicationDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogActivityAsync(string userId, string userEmail, string action, string? description = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return;

            try
            {
                var auditLog = new AuditLog
                {
                    UserId = userId,
                    UserEmail = userEmail,
                    Action = action,
                    Description = description,
                    IpAddress = GetClientIpAddress(httpContext),
                    UserAgent = httpContext.Request.Headers["User-Agent"].ToString(),
                    SessionId = httpContext.Session.Id,
                    Timestamp = DateTime.UtcNow
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
            }
            catch
            {
                // If AuditLogs table is missing or has wrong schema, don't break login/register
            }
        }

        private string GetClientIpAddress(HttpContext httpContext)
        {
            // Check for forwarded IP (if behind proxy/load balancer)
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            return httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        /// <summary>
        /// Get audit logs for a user, most recent first. Optional maxCount (default 200) to limit rows.
        /// </summary>
        public async Task<List<AuditLog>> GetUserActivitiesAsync(string userId, int? maxCount = 200)
        {
            var limit = (maxCount.HasValue && maxCount.Value > 0) ? maxCount.Value : 200;
            return await _context.AuditLogs
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.Timestamp)
                .Take(limit)
                .ToListAsync();
        }

        public async Task<bool> HasActiveSessionAsync(string userId, string currentSessionId)
        {
            // Check if user has other active sessions (different session IDs)
            var otherSessions = await _context.AuditLogs
                .Where(a => a.UserId == userId 
                    && a.SessionId != currentSessionId 
                    && a.Action == "Login"
                    && a.Timestamp > DateTime.UtcNow.AddMinutes(-1)) // Within session timeout
                .Select(a => a.SessionId)
                .Distinct()
                .ToListAsync();

            return otherSessions.Any();
        }

        /// <summary>
        /// Returns the SessionId of the most recent Login, 2FA Login, or Register for this user.
        /// Used to enforce single session: only this session is valid; others are signed out.
        /// </summary>
        public async Task<string?> GetCurrentSessionIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId)) return null;
            try
            {
                var latest = await _context.AuditLogs
                    .Where(a => a.UserId == userId && (a.Action == "Login" || a.Action == "Register" || a.Action == "2FA Login"))
                    .OrderByDescending(a => a.Timestamp)
                    .Select(a => a.SessionId)
                    .FirstOrDefaultAsync();
                return latest;
            }
            catch
            {
                return null;
            }
        }
    }
}
