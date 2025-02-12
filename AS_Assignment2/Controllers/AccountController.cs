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
using AS_Assignment2.Services;

public class AccountController : Controller
{
    private readonly UserManager<UserClass> _userManager;
    private readonly SignInManager<UserClass> _signInManager;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<AccountController> _logger;
    private readonly IConfiguration _configuration;
    private readonly ICustomEmailSender _emailSender;


    private readonly AuthDbContext _context;
    private const int MaxFailedAttempts = 3;
    private readonly TimeSpan LockoutDuration = TimeSpan.FromSeconds(30);


    public AccountController(
    UserManager<UserClass> userManager,
    SignInManager<UserClass> signInManager,
    IEncryptionService encryptionService,
    ICustomEmailSender emailSender,
    IConfiguration configuration,
    ILogger<AccountController> logger,
        AuthDbContext context)
    {
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryptionService = encryptionService;
            _emailSender = emailSender;
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
            return RedirectToAction("Error", "Error", new { statusCode = 500 });
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

                    // Handle locked accounts
                    if (user.IsLockedOut)
                    {
                        if (user.LockoutEndTime.HasValue && user.LockoutEndTime.Value > DateTime.UtcNow)
                        {
                            var timeLeft = user.LockoutEndTime.Value - DateTime.UtcNow;
                            ModelState.AddModelError("",
                                $"Account locked. Try again in {timeLeft.Minutes} minutes");
                            return View(model);
                        }
                        else
                        {
                            user.IsLockedOut = false;
                            user.FailedLoginAttempts = 0;
                            user.LockoutEndTime = null;
                            await _userManager.UpdateAsync(user);
                        }
                    }


                    // Track login attempt
                    _context.LoginAttempts.Add(new LoginAttempt
                    {
                        UserId = user.Id,
                        AttemptTime = DateTime.UtcNow,
                        IsSuccessful = false,
                        IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });

                    // Check password without signing in
                    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);


                    if (result.Succeeded)
                    {
                        // Check password expiration
                        var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays");
                        if ((DateTime.UtcNow - user.PasswordLastChanged).TotalDays > maxAgeDays)
                        {
                            ModelState.AddModelError("",
                                $"Password expired {Math.Floor((DateTime.UtcNow - user.PasswordLastChanged).TotalDays - maxAgeDays)} days ago");
                            return View(model);
                        }

                        // Generate and send OTP
                        string otp = GenerateOtp();
                        await SendOtpEmail(user.Email, otp);

                        // Store OTP and email in session
                        HttpContext.Session.SetString("Otp", otp);
                        HttpContext.Session.SetString("OtpEmail", user.Email);

                        // Ensure session is persisted before redirect
                        await HttpContext.Session.CommitAsync();

                        TempData["SuccessMessage"] = "OTP sent to your email. Please check and enter below.";
                        return RedirectToAction("Otp");
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
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt");
                        _logger.LogWarning("Failed login attempt for {Email}", model.Email);
                    }
                }
                else
                {
                    // Generic error message to prevent account enumeration
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                }
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

            // Check minimum password age
            var minAgeSeconds = _configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeSeconds");
            if ((DateTime.UtcNow - user.PasswordLastChanged).TotalSeconds < minAgeSeconds)
            {
                ModelState.AddModelError("",
                    $"Password cannot be changed within {minAgeSeconds} seconds");
                return View(model);
            }

            // Check password history
            var historySize = _configuration.GetValue<int>("PasswordPolicy:PasswordHistorySize");
            var previousHashes = user.PasswordHistory?
                .Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Take(historySize) ?? Enumerable.Empty<string>();

            var hasher = _userManager.PasswordHasher;

            // Verify against all historical hashes
            foreach (var oldHash in previousHashes)
            {
                if (hasher.VerifyHashedPassword(user, oldHash, model.NewPassword)
                    == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("NewPassword",
                        "Cannot reuse recent passwords");
                    return View(model);
                }
            }

            // Verify current password
            var isCurrentPasswordValid = await _userManager.CheckPasswordAsync(user, model.OldPassword);
            if (!isCurrentPasswordValid)
            {
                ModelState.AddModelError("OldPassword", "Current password is incorrect");
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

            // Update password history with OLD hash
            var updatedHistory = new[] { user.PasswordHash } // Store previous hash before change
                .Concat(previousHashes)
                .Take(historySize)
                .ToArray();

            user.PasswordHistory = string.Join(";", updatedHistory);
            user.PasswordLastChanged = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Audit log
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "Password Changed",
                Details = "User changed their password"
            });
            await _context.SaveChangesAsync();

            // Re-sign in user
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

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPassword model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var sanitizedEmail = InputSanitizer.Sanitize(model.Email);
        var user = await _userManager.FindByEmailAsync(sanitizedEmail);

        if (user == null)
            return RedirectToAction(nameof(ForgotPasswordConfirmation));

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.Action(
            nameof(ResetPassword),
            "Account",
            new { token, email = user.Email },
            protocol: Request.Scheme
        );

        var message = new Message(
            new[] { user.Email },
            "Password Reset Request",
            $"Please reset your password by clicking here: {callbackUrl}"
        );

        // Check if _emailSender is null
        if (_emailSender == null)
        {
            throw new InvalidOperationException("Email sender is not initialized.");
        }

        try
        {
            await _emailSender.SendEmailAsync(message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email to {Email}", user.Email);
            ModelState.AddModelError("", "An error occurred while sending the email.");
            return View(model);
        }

        return RedirectToAction(nameof(ForgotPasswordConfirmation));
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string token, string email)
    {
        var model = new ResetPassword { Token = token, Email = email };
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPassword model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return RedirectToAction(nameof(ResetPasswordConfirmation));

        // Check password history
        var hasher = _userManager.PasswordHasher;
        var newPasswordHash = hasher.HashPassword(user, model.Password);
        var previousHashes = user.PasswordHistory?
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Take(_configuration.GetValue<int>("PasswordPolicy:PasswordHistorySize"))
            ?? Enumerable.Empty<string>();

        foreach (var oldHash in previousHashes)
        {
            if (hasher.VerifyHashedPassword(user, oldHash, model.Password)
                == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("Password",
                    "Cannot reuse recent passwords");
                return View(model);
            }
        }

        var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
            return View();
        }

        // Update password history
        var updatedHistory = new[] { user.PasswordHash }
            .Concat(previousHashes)
            .Take(_configuration.GetValue<int>("PasswordPolicy:PasswordHistorySize"))
            .ToArray();

        user.PasswordHistory = string.Join(";", updatedHistory);
        user.PasswordLastChanged = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return RedirectToAction(nameof(ResetPasswordConfirmation));
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Otp()
    {
        var storedEmail = HttpContext.Session.GetString("OtpEmail");

        if (string.IsNullOrEmpty(storedEmail))
        {
            return RedirectToAction("Login");
        }

        return View(new Otp { Email = storedEmail });
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Otp(Otp model)
    {
        if (!ModelState.IsValid)
        {
            TempData["ErrorMessage"] = "Please enter a valid OTP.";
            return View(model);
        }

        var storedOtp = HttpContext.Session.GetString("Otp");
        var storedEmail = HttpContext.Session.GetString("OtpEmail");

        if (storedOtp == null || model.OTP != storedOtp || storedEmail != model.Email)
        {
            TempData["ErrorMessage"] = "Invalid OTP. Please try again.";
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            TempData["ErrorMessage"] = "User not found.";
            return RedirectToAction("Login");
        }

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
            Details = "Successful login with OTP"
        });
        await _context.SaveChangesAsync();

        // Sign in the user
        await _signInManager.SignInAsync(user, isPersistent: false);

        // Clear OTP session data
        HttpContext.Session.Remove("Otp");
        HttpContext.Session.Remove("OtpEmail");

        _logger.LogInformation("User {Email} logged in with OTP", model.Email);
        return RedirectToAction("Index", "Home");
    }

    private string GenerateOtp()
    {
        Random random = new Random();
        return random.Next(100000, 999999).ToString();
    }

    private async Task SendOtpEmail(string email, string otp)
    {
        var message = new Message(
            new[] { email },
            "Your OTP Code",
            $"Your verification code is: {otp}"
        );

        await _emailSender.SendEmailAsync(message);
    }
}