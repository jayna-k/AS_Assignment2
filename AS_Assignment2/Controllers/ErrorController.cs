using AS_Assignment2.Models;
using AS_Assignment2.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AS_Assignment2.Controllers
{
    public class ErrorController : Controller
    {
        private readonly ILogger<ErrorController> _logger;

        public ErrorController(ILogger<ErrorController> logger)
        {
            _logger = logger;
        }

        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            var vm = new ErrorViewModel
            {
                StatusCode = statusCode,
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            switch (statusCode)
            {
                case 403:
                    vm.ErrorMessage = "Access Denied/Forbidden";
                    _logger.LogWarning($"403 Forbidden Error occurred. Request ID: {vm.RequestId}");
                    break;
                case 404:
                    vm.ErrorMessage = "Resource not found";
                    _logger.LogWarning($"404 Not Found Error occurred. Request ID: {vm.RequestId}");
                    break;
                case 500:
                    vm.ErrorMessage = "Internal Server Error";
                    _logger.LogError($"500 Internal Server Error occurred. Request ID: {vm.RequestId}");
                    break;
                default:
                    vm.ErrorMessage = $"Unexpected error: {statusCode}";
                    _logger.LogError($"{statusCode} Error occurred. Request ID: {vm.RequestId}");
                    break;
            }

            return View("Error", vm);
        }

        [Route("Error")]
        public IActionResult GlobalErrorHandler()
        {
            var vm = new ErrorViewModel
            {
                StatusCode = 500,
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                ErrorMessage = "An unexpected error occurred"
            };

            _logger.LogError($"Global error handler triggered. Request ID: {vm.RequestId}");
            return View("Error", vm);
        }
    }
}
