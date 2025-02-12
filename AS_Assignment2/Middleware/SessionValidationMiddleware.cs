using Microsoft.AspNetCore.Http;
using AS_Assignment2.Models;
using AS_Assignment2.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using Microsoft.Extensions.Logging;

namespace AS_Assignment2.Middleware
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next; private readonly ILogger<SessionValidationMiddleware> _logger;

        public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(
            HttpContext context,
            AuthDbContext dbContext,
            SignInManager<UserClass> signInManager,
            UserManager<UserClass> userManager)
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                var sessionToken = context.Session.GetString("SessionToken");

                if (string.IsNullOrEmpty(sessionToken))
                {
                    await PerformFullLogout(context, dbContext, signInManager, userManager);
                    return;
                }

                var session = await dbContext.Sessions
                    .FirstOrDefaultAsync(s => s.SessionToken == sessionToken && s.EndTime == null);

                if (session == null || DateTime.UtcNow > session.StartTime.AddMinutes(10))
                {
                    await PerformFullLogout(context, dbContext, signInManager, userManager, session);
                    return;
                }
            }

            await _next(context);
        }

        private async Task PerformFullLogout(
            HttpContext context,
            AuthDbContext dbContext,
            SignInManager<UserClass> signInManager,
            UserManager<UserClass> userManager,
            Session session = null)
        {
            try
            {
                // Check if logout has already been initiated
                if (context.Items.ContainsKey("LogoutInitiated") && (bool)context.Items["LogoutInitiated"])
                {
                    return; // Prevent repeated logout calls
                }

                context.Items["LogoutInitiated"] = true; // Mark logout as initiated

                var user = await userManager.GetUserAsync(context.User);

                if (user != null)
                {
                    // Add audit log
                    dbContext.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Logout",
                        Details = "User  logged out due to session expiration"
                    });

                    // Update session from the passed parameter if available
                    if (session != null)
                    {
                        session.EndTime = DateTime.UtcNow;
                    }
                    else
                    {
                        // If session not passed, retrieve using sessionToken
                        var sessionToken = context.Session.GetString("SessionToken");
                        if (!string.IsNullOrEmpty(sessionToken))
                        {
                            var existingSession = await dbContext.Sessions
                                .FirstOrDefaultAsync(s => s.SessionToken == sessionToken);
                            if (existingSession != null)
                            {
                                existingSession.EndTime = DateTime.UtcNow;
                            }
                        }
                    }

                    await dbContext.SaveChangesAsync();
                }

                // Sign out and clear session
                await signInManager.SignOutAsync();
                context.Session.Clear();
                context.Response.Cookies.Delete(".AspNetCore.Session");
                _logger.LogInformation("User  logged out");

                // Redirect to login
                context.Response.Redirect("/Account/Login");
                context.Response.StatusCode = StatusCodes.Status302Found; // Optional
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during automatic logout");
                context.Response.Redirect("/Account/Login");
                context.Response.StatusCode = StatusCodes.Status302Found; // Optional
            }
        }
    }
}