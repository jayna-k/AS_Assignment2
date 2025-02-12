using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class Login
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email Address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
            ErrorMessage = "Password must contain:")]
        [MinLength(12, ErrorMessage = "Password must be at least 12 characters")]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [HiddenInput]
        public string RecaptchaToken { get; set; }

    }
}
