using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class LoginAttempts
    {
        public int Id { get; set; }

        public int UserId { get; set; } // Foreign key to User

        [Required]
        public DateTime AttemptTime { get; set; }

        [Required]
        public bool IsSuccessful { get; set; }

        public string IPAddress { get; set; }
    }
}
