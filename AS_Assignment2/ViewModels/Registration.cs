using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class RegisterViewModel
{
    [Required]
    [Display(Name = "First Name")]
    [RegularExpression(@"^[a-zA-Z \-']{1,50}$", ErrorMessage = "Invalid characters")]
    public string FirstName { get; set; }

    [Required]
    [Display(Name = "Last Name")]
    [RegularExpression(@"^[a-zA-Z \-']{1,50}$", ErrorMessage = "Invalid characters")]
    public string LastName { get; set; }

    [Required]
    [Display(Name = "Credit Card Number")]
    [RegularExpression(@"^[0-9]{13,16}$",
        ErrorMessage = "Credit card number must be 13-16 digits")]
    public string CreditCardNo { get; set; }

    [Required]
    [Phone]
    [Display(Name = "Mobile Number")]
    [RegularExpression(@"^[0-9]{8,}$", ErrorMessage = "Invalid phone number")]
    public string MobileNo { get; set; }

    [Required]
    [Display(Name = "Billing Address")]
    [StringLength(200, MinimumLength = 5)]
    public string BillingAddress { get; set; }

    [Required]
    [Display(Name = "Shipping Address")]
    public string ShippingAddress { get; set; }

    [Required]
    [EmailAddress]
    [Remote(action: "VerifyEmail", controller: "Account", ErrorMessage = "Email is already in use.")]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
        ErrorMessage = "Password must be at least 12 characters with uppercase, lowercase, number, and special character")] 
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; }

    [DataType(DataType.Upload)]
    [AllowedExtensions(new[] { ".jpg", ".jpeg" }, ErrorMessage = "Only JPG/JPEG files are allowed")]
    public IFormFile? Photo { get; set; }
}

// Attributes/AllowedExtensionsAttribute.cs
public class AllowedExtensionsAttribute : ValidationAttribute
{
    private readonly string[] _extensions;

    public AllowedExtensionsAttribute(string[] extensions)
    {
        _extensions = extensions;
    }

    protected override ValidationResult IsValid(
        object value, ValidationContext validationContext)
    {
        if (value is IFormFile file)
        {
            var extension = Path.GetExtension(file.FileName);
            if (!_extensions.Contains(extension.ToLower()))
            {
                return new ValidationResult(GetErrorMessage());
            }
        }
        return ValidationResult.Success;
    }

    public string GetErrorMessage()
    {
        return $"Allowed file extensions: {string.Join(", ", _extensions)}";
    }
}
