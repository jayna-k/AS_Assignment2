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

public class AccountController : Controller
{
    private readonly UserManager<UserClass> _userManager;
    private readonly SignInManager<UserClass> _signInManager;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<AccountController> _logger;

    private readonly AuthDbContext _context;
    private const int MaxFailedAttempts = 3;
    private readonly TimeSpan LockoutDuration = TimeSpan.FromSeconds(30);


    public AccountController(
    UserManager<UserClass> userManager,
    SignInManager<UserClass> signInManager,
    IEncryptionService encryptionService,
    ILogger<AccountController> logger,
        AuthDbContext context)
    {
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryptionService = encryptionService;
            _logger = logger;
            _context = context;

        }
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyEmail(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
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
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    CreditCardNo = encryptedCard,
                    MobileNo = model.MobileNo,
                    BillingAddress = model.BillingAddress,
                    ShippingAddress = model.ShippingAddress,
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

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(Login model)
    {
        try
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

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

                        // Add audit log
                        _context.AuditLogs.Add(new AuditLog
                        {
                            UserId = user.Id,
                            Action = "Login",
                            Details = "Successful login"
                        });
                        await _context.SaveChangesAsync();


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

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
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
        }

        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();
        _logger.LogInformation("User logged out");
        return RedirectToAction("Login");
    }


    [HttpGet]
    [AllowAnonymous]
    public IActionResult Lockout()
    {
        ViewData["LockoutDuration"] = (int)LockoutDuration.TotalSeconds;
        ViewData["LockoutMilliseconds"] = (int)LockoutDuration.TotalMilliseconds;
        return View();
    }

}