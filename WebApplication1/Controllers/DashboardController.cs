using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;
using WebApplication1.Services;
using Microsoft.AspNetCore.Authentication;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EncryptionService _encryptionService;

        public DashboardController(UserManager<ApplicationUser> userManager, EncryptionService encryptionService)
        {
            _userManager = userManager;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> Index()
        {
            if (HttpContext.Session.GetString("UserId") == null)
            {
                await HttpContext.SignOutAsync();
                TempData["SessionExpired"] = "Your session has expired. Please login again.";
                return RedirectToAction("Login", "Account");
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login", "Account");

            string decryptedNRIC = _encryptionService.Decrypt(user.NRIC);
            var userInfo = new
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Gender = user.Gender,
                NRIC = decryptedNRIC,
                DateOfBirth = user.DateOfBirth.ToString("yyyy-MM-dd"),
                ResumeFileName = user.ResumeFileName,
                ResumeFilePath = user.ResumeFilePath,
                WhoAmI = user.WhoAmI
            };
            ViewBag.UserInfo = userInfo;
            return View();
        }
    }
}
