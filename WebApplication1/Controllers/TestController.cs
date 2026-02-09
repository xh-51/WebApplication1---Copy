using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    /// <summary>
    /// Test controller to demonstrate error pages
    /// Remove this in production!
    /// </summary>
    public class TestController : Controller
    {
        [Route("Test/Error404")]
        public IActionResult Test404()
        {
            return NotFound(); // This will trigger 404 error page
        }

        [Route("Test/Error403")]
        public IActionResult Test403()
        {
            return StatusCode(403); // This will trigger 403 error page
        }

        [Route("Test/Error500")]
        public IActionResult Test500()
        {
            return StatusCode(500); // This will trigger 500 error page
        }

        [Route("Test/ThrowException")]
        public IActionResult ThrowException()
        {
            throw new Exception("This is a test exception to demonstrate error handling.");
        }

        [Route("Test/InvalidPage")]
        public IActionResult InvalidPage()
        {
            // This page doesn't exist, will show 404
            return View("NonExistentView");
        }
    }
}
