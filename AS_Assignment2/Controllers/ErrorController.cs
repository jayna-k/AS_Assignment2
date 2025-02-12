using AS_Assignment2.Models;
using AS_Assignment2.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AS_Assignment2.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode?}")]
        public IActionResult HttpStatusCodeHandler(int? statusCode)
        {
            var errorViewModel = new ErrorViewModel
            {
                StatusCode = statusCode,
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            // Customize messages based on status code
            errorViewModel.ErrorMessage = statusCode switch
            {
                400 => "The server cannot process your request due to invalid syntax.",
                401 => "Authentication is required to access this resource.",
                403 => "You do not have permission to view this page.",
                404 => "The page you requested does not exist.",
                405 => "The HTTP method used is not allowed for this resource.",
                500 => "An unexpected error occurred on the server.",
                _ => "An error occurred while processing your request."
            };

            return View("Error", errorViewModel);
        }
    }
}
