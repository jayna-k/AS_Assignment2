using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class Otp
    {
        [Required(ErrorMessage = "OTP is required.")]
        [StringLength(6, ErrorMessage = "OTP must be 6 digits long.", MinimumLength = 6)]
        [Display(Name = "OTP Code")]
        public string OTP { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}