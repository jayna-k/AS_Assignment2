using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class Otp
    {
        [Required]
        public string Email { get; set; }

        [Required]
        [StringLength(6, MinimumLength = 6)]
        public string OTP { get; set; }
    }
}
