using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AS_Assignment2.Models;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using static AS_Assignment2.Services.AesEncryption;
using Microsoft.Extensions.Logging;
using AS_Assignment2.ViewModels;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Text.RegularExpressions;

public class AccountController : Controller
{
    private readonly UserManager<UserClass> _userManager;
    private readonly SignInManager<UserClass> _signInManager;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<AccountController> _logger;
    private readonly IConfiguration _configuration;


    private readonly AuthDbContext _context;
    private const int MaxFailedAttempts = 3;
    private readonly TimeSpan LockoutDuration = TimeSpan.FromSeconds(30);


    public AccountController(
    UserManager<UserClass> userManager,
    SignInManager<UserClass> signInManager,
    IEncryptionService encryptionService,
    IConfiguration configuration,
    ILogger<AccountController> logger,
        AuthDbContext context)
    {
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryptionService = encryptionService;
            _configuration = configuration;
            _logger = logger;
            _context = context;

        }
    }


    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyEmail(string email)
    {
        var sanitizedEmail = InputSanitizer.Sanitize(email);
        var user = await _userManager.FindByEmailAsync(sanitizedEmail);
        if (user != null)
        {
            return Json($"Email {email} is already in use.");
        }
        return Json(true);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        try
        {

            if (ModelState.IsValid)
            {
                var encryptedCard = EncryptCreditCard(model.CreditCardNo);
                _logger.LogInformation("Encrypted CC Length: {Length}", encryptedCard.Length);
                _logger.LogDebug("Encrypted CC Value: {Value}", encryptedCard);

                var user = new UserClass
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = System.Net.WebUtility.HtmlEncode(model.FirstName),
                    LastName = System.Net.WebUtility.HtmlEncode(model.LastName),
                    BillingAddress = System.Net.WebUtility.HtmlEncode(model.BillingAddress),
                    ShippingAddress = System.Net.WebUtility.HtmlEncode(model.ShippingAddress),
                    CreditCardNo = encryptedCard,
                    MobileNo = model.MobileNo,
                    PhotoPath = model.Photo != null ? await SavePhoto(model.Photo) : null
                };

                _logger.LogInformation("Attempting to create user: {User}", user);
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                if (result.Succeeded)
                {
                    // Audit log
                    _context.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Registration",
                        Details = "New user registered"
                    });
                    await _context.SaveChangesAsync();
                }
            }

            return View(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration error for {Email}", model.Email);
            ModelState.AddModelError("", "An error occurred during registration. Please try again.");
        }
        return View(model);

    }

    private string EncryptCreditCard(string creditCardNo)
    {
        return _encryptionService.Encrypt(creditCardNo); // Use the injected service
    }


    private async Task<string> SavePhoto(IFormFile photo)
    {
        var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images", "photos");
        if (!Directory.Exists(uploadsFolder))
        {
            Directory.CreateDirectory(uploadsFolder);
        }

        var uniqueFileName = Guid.NewGuid().ToString() + "_" + photo.FileName;
        var filePath = Path.Combine(uploadsFolder, uniqueFileName);

        using (var fileStream = new FileStream(filePath, FileMode.Create))
        {
            await photo.CopyToAsync(fileStream);
        }

        return Path.Combine("images", "photos", uniqueFileName);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login()
    {
        return View(new Login());
    }

    public static class InputSanitizer
    {
        private static readonly Regex _sqlInjectionRegex = new Regex(
            @"(\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})\b|;)|(\-\-)|(''?)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static string Sanitize(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return input;
            return _sqlInjectionRegex.Replace(input, match => string.Empty);
        }
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(Login model)
    {
        try
        {
            if (ModelState.IsValid)
            {
                // Verify reCAPTCHA first
                var recaptchaValid = await ValidateCaptcha(model.RecaptchaToken);
                if (!recaptchaValid)
                {
                    ModelState.AddModelError(string.Empty, "Security verification failed");
                    return View(model);
                }

                HttpContext.Session.Clear();

                var sanitizedEmail = InputSanitizer.Sanitize(model.Email);
                var user = await _userManager.FindByEmailAsync(sanitizedEmail);


                if (user != null)
                {
                    // Track login attempt
                    _context.LoginAttempts.Add(new LoginAttempt
                    {
                        UserId = user.Id,
                        AttemptTime = DateTime.UtcNow,
                        IsSuccessful = false,
                        IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });

                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName,
                        model.Password,
                        isPersistent: false, // Set to true for "remember me" functionality
                        lockoutOnFailure: true);

                    if (result.Succeeded)
                    {
                        // Update attempt to successful
                        var attempt = _context.LoginAttempts.Local.Last();
                        attempt.IsSuccessful = true;

                        // Terminate existing sessions
                         var activeSessions = await _context.Sessions
                        .Where(s => s.UserId == user.Id && s.EndTime == null)
                        .ToListAsync();

                    foreach (var session in activeSessions)
                    {
                        session.EndTime = DateTime.UtcNow;
                    }

                    // Create new session
                    var newSession = new Session
                    {
                        UserId = user.Id,
                        StartTime = DateTime.UtcNow,
                        SessionToken = Guid.NewGuid().ToString()
                    };

                    _context.Sessions.Add(newSession);
                    await _context.SaveChangesAsync();

                    HttpContext.Session.SetString("SessionToken", newSession.SessionToken);

                        // Add audit log
                        _context.AuditLogs.Add(new AuditLog
                        {
                            UserId = user.Id,
                            Action = "Login",
                            Details = "Successful login"
                        });
                        await _context.SaveChangesAsync();

                        HttpContext.Session.SetString("SessionToken", newSession.SessionToken);
                        _logger.LogInformation("User {Email} logged in", model.Email);
                        return RedirectToAction("Index", "Home");
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        // Implement 2FA if needed
                        return RedirectToPage("./LoginWith2fa");
                    }
                    else if (result.IsLockedOut)
                    {
                        _context.AuditLogs.Add(new AuditLog
                        {
                            UserId = user.Id,
                            Action = "Account Locked",
                            Details = "Account locked due to multiple failed attempts"
                        });
                        await _context.SaveChangesAsync();
                        _logger.LogWarning("User {Email} locked out", model.Email);
                        return RedirectToAction("Lockout");
                    }
                }

                // Generic error message to prevent account enumeration
                ModelState.AddModelError(string.Empty, "Invalid login attempt");
                _logger.LogWarning("Failed login attempt for {Email}", model.Email);
            }
            return View(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error for {Email}", model.Email);
            ModelState.AddModelError("", "An error occurred during login");
            return View(model);
        }
    }


    private async Task<bool> ValidateCaptcha(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("Empty reCAPTCHA token");
            return false;
        }

        try
        {
            using var client = new HttpClient();
            var secret = _configuration["Recaptcha:SecretKey"];
            var minScore = _configuration.GetValue<double>("Recaptcha:MinScore", 0.5);

            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={token}",
                null
            );

            var responseString = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<RecaptchaResponse>(responseString);

            _logger.LogInformation("reCAPTCHA validation result: {Success} Score: {Score} Action: {Action}",
                result.Success, result.Score, result.Action);

            return result.Success &&
                   result.Action == "login" &&
                   result.Score >= minScore;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "reCAPTCHA validation error");
            return false;
        }
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Logout",
                    Details = "User logged out"
                });
                await _context.SaveChangesAsync();

                var sessionToken = HttpContext.Session.GetString("SessionToken");
                if (!string.IsNullOrEmpty(sessionToken))
                {
                    var session = await _context.Sessions
                        .FirstOrDefaultAsync(s => s.SessionToken == sessionToken);

                    if (session != null)
                    {
                        session.EndTime = DateTime.UtcNow;
                    }
                }

                await _context.SaveChangesAsync();
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            _logger.LogInformation("User logged out");
            return RedirectToAction("Login", "Account");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return RedirectToAction("Login", "Account");
        }

    }


    [HttpGet]
    [AllowAnonymous]
    public IActionResult Lockout()
    {
        ViewData["LockoutDuration"] = (int)LockoutDuration.TotalSeconds;
        ViewData["LockoutMilliseconds"] = (int)LockoutDuration.TotalMilliseconds;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExtendSession()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user != null)
        {
            var sessionToken = HttpContext.Session.GetString("SessionToken");
            if (!string.IsNullOrEmpty(sessionToken))
            {
                var session = await _context.Sessions
                    .FirstOrDefaultAsync(s => s.SessionToken == sessionToken);

                if (session != null)
                {
                    session.StartTime = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                    return Ok();
                }
            }
        }
        return Unauthorized();
    }

    [Authorize]
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePassword model)
    {
        if (model == null)
        {
            ModelState.AddModelError("", "Invalid request data");
            return View(new ChangePassword());
        }

        try
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return RedirectToAction("Login");

            // Add null check for password fields
            if (string.IsNullOrEmpty(model.OldPassword) || string.IsNullOrEmpty(model.NewPassword))
            {
                ModelState.AddModelError("", "Password fields cannot be empty");
                return View(model);
            }

            // Verify current password
            var isCurrentPasswordValid = await _userManager.CheckPasswordAsync(user, model.OldPassword);
            if (!isCurrentPasswordValid)
            {
                ModelState.AddModelError("OldPassword", "Current password is incorrect");
                return View(model);
            }

            // Check if new password is same as old
            if (model.OldPassword == model.NewPassword)
            {
                ModelState.AddModelError("NewPassword", "New password must be different from current password");
                return View(model);
            }

            // Change password
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);
                return View(model);
            }

            // Audit log
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "Password Changed",
                Details = "User changed their password"
            });
            await _context.SaveChangesAsync();

            // Re-sign in user to refresh authentication cookie
            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User {UserId} changed password successfully", user.Id);

            return RedirectToAction("Index", "Home");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password change error");
            ModelState.AddModelError("", "An error occurred while changing password");
            return View(model);
        }
    }
}