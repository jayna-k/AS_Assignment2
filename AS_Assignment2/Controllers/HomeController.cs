using System.Diagnostics;
using AS_Assignment2.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AS_Assignment2.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _contxt;
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<UserClass> _userManager;

        // Add UserManager to constructor
        public HomeController(
            ILogger<HomeController> logger,
            IHttpContextAccessor httpContextAccessor,
            UserManager<UserClass> userManager)
        {
            _logger = logger;
            _contxt = httpContextAccessor;
            _userManager = userManager;
        }

        [Authorize]
        public async Task<IActionResult> Index()
        {
            // Get the current user
            var user = await _userManager.GetUserAsync(User);

            // Set session values using actual user data
            _contxt.HttpContext.Session.SetString("StudentName", $"{user.FirstName} {user.LastName}");
            _contxt.HttpContext.Session.SetString("StudentId", user.Id);

            return View(user);
        }

        public IActionResult Privacy()
        {
            string studentName = _contxt.HttpContext.Session.GetString("StudentName");
            // You might want to actually use the studentName variable
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}