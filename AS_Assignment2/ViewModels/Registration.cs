using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class Register
    {
        public int Id { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [StringLength(50, ErrorMessage = "First name cannot be longer than 50 characters.")]
        public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [StringLength(50, ErrorMessage = "Last name cannot be longer than 50 characters.")]
        public string LastName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit card number must be 16 digits.")]
        public string CreditCardNo { get; set; }

        [Required]
        [DataType(DataType.PhoneNumber)]
        [RegularExpression(@"^\+?[1-9]\d{1,14}$", ErrorMessage = "Invalid phone number format.")]
        public string MobileNo { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string BillingAddress { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string ShippingAddress { get; set; }

        [DataType(DataType.Upload)]
        [FileExtensions(Extensions = "jpg,jpeg", ErrorMessage = "Please upload a file with .jpg or .jpeg extension.")]
        public IFormFile Photo { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        [EmailAddress(ErrorMessage = "Invalid email address format.")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
