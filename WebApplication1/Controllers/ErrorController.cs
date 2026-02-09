using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            ViewBag.StatusCode = statusCode;
            ViewBag.ErrorMessage = GetErrorMessage(statusCode);
            
            return View("Error");
        }

        [Route("Error")]
        public IActionResult Error()
        {
            // Get the status code from the response
            var statusCode = HttpContext.Response.StatusCode;
            if (statusCode == 200)
            {
                statusCode = 500; // Default to 500 if no status code set
            }

            ViewBag.StatusCode = statusCode;
            ViewBag.ErrorMessage = GetErrorMessage(statusCode);
            
            return View("Error");
        }

        private string GetErrorMessage(int statusCode)
        {
            return statusCode switch
            {
                400 => "Bad Request - The request was invalid.",
                401 => "Unauthorized - You need to login to access this page.",
                403 => "Forbidden - You don't have permission to access this resource.",
                404 => "Page Not Found - The page you're looking for doesn't exist.",
                500 => "Internal Server Error - Something went wrong on our end.",
                502 => "Bad Gateway - The server received an invalid response.",
                503 => "Service Unavailable - The service is temporarily unavailable.",
                _ => "An error occurred while processing your request."
            };
        }
    }
}
