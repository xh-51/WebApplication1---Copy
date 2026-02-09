using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class AuditLogController : Controller
    {
        private readonly AuditLogService _auditLogService;

        public AuditLogController(AuditLogService auditLogService)
        {
            _auditLogService = auditLogService;
        }

        /// <summary>
        /// Show audit logs for the current user (login, logout, register, etc.).
        /// </summary>
        public async Task<IActionResult> Index()
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return RedirectToAction("Login", "Account");

            var logs = await _auditLogService.GetUserActivitiesAsync(userId);
            return View(logs);
        }
    }
}
