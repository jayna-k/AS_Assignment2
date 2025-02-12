using System.Text.RegularExpressions;

namespace AS_Assignment2.Middleware
{
    public class InputValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<InputValidationMiddleware> _logger;

        public InputValidationMiddleware(RequestDelegate next, ILogger<InputValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check for potential XSS in query strings
            foreach (var (key, value) in context.Request.Query)
            {
                if (IsDangerousString(value.ToString()))
                {
                    _logger.LogWarning($"XSS attempt detected in query string: {key}={value}");
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Invalid input detected");
                    return;
                }
            }

            // Check for potential XSS in form data
            if (context.Request.HasFormContentType)
            {
                var form = await context.Request.ReadFormAsync();
                foreach (var (key, value) in form)
                {
                    if (IsDangerousString(value.ToString()))
                    {
                        _logger.LogWarning($"XSS attempt detected in form field: {key}={value}");
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        await context.Response.WriteAsync("Invalid input detected");
                        return;
                    }
                }
            }

            await _next(context);
        }

        private bool IsDangerousString(string input)
        {
            return Regex.IsMatch(input, @"<[^>]*>|&lt;|&gt;|javascript:",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }
    }
}
