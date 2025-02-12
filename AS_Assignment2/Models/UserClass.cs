using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.Models
{
	public class UserClass : IdentityUser
	{
		public string FirstName { get; set; }
		public string LastName { get; set; }
        [MaxLength(500)]
        public string CreditCardNo { get; set; }
		public string MobileNo { get; set; }
		public string BillingAddress { get; set; }
		public string ShippingAddress { get; set; }
		public string? PhotoPath { get; set; }
        public string? OTP { get; set; }
        public int FailedLoginAttempts { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTime? LockoutEndTime { get; set; }
        public DateTime PasswordLastChanged { get; set; } = DateTime.UtcNow;
        public string PasswordHistory { get; set; } = "";
    }
}
