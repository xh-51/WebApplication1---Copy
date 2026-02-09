using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using System.Net;
using WebApplication1.Models;
using WebApplication1.Services;
using Microsoft.AspNetCore.Authentication;

namespace WebApplication1.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly EncryptionService _encryptionService;

        public HomeController(UserManager<ApplicationUser> userManager, EncryptionService encryptionService)
        {
            _userManager = userManager;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> Index()
        {
            // Logged-in users go to Dashboard
            if (User.Identity?.IsAuthenticated == true)
            {
                if (HttpContext.Session.GetString("UserId") == null)
                {
                    await HttpContext.SignOutAsync();
                    TempData["SessionExpired"] = "Your session has expired. Please login again.";
                    return RedirectToAction("Login", "Account");
                }
                return RedirectToAction("Index", "Dashboard");
            }
            return View();
        }
    }
}
