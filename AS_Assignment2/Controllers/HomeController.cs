using System.Diagnostics;
using AS_Assignment2.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AS_Assignment2.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor contxt;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IHttpContextAccessor httpContextAccessor)
        {
            _logger = logger;
            contxt = httpContextAccessor;
        }

        public IActionResult Index()
        {
            contxt.HttpContext.Session.SetString("StudentName", "Tim");
            contxt.HttpContext.Session.SetInt32("StudentId", 50);
            return View();
        }

        public IActionResult Privacy()
        {
            string StudentName = contxt.HttpContext.Session.GetString("StudentName");
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
