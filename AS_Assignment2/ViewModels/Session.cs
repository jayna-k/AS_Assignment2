using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class Session
    {
        public int Id { get; set; }

        public int UserId { get; set; } // Foreign key to User

        [Required]
        public DateTime StartTime { get; set; }

        public DateTime EndTime { get; set; }

        public string SessionToken { get; set; }
    }
}
