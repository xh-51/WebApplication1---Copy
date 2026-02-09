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

        public async Task<List<AuditLog>> GetUserActivitiesAsync(string userId)
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.Timestamp)
                .ToListAsync();
        }

        public async Task<bool> HasActiveSessionAsync(string userId, string currentSessionId)
        {
            // Check if user has other active sessions (different session IDs)
            var otherSessions = await _context.AuditLogs
                .Where(a => a.UserId == userId 
                    && a.SessionId != currentSessionId 
                    && a.Action == "Login"
                    && a.Timestamp > DateTime.UtcNow.AddMinutes(-20)) // Within session timeout
                .Select(a => a.SessionId)
                .Distinct()
                .ToListAsync();

            return otherSessions.Any();
        }
    }
}
