using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class AuditLog
    {
        public int Id { get; set; }

        public int UserId { get; set; } // Foreign key to User

        [Required]
        public DateTime ActionTime { get; set; }

        [Required]
        public string Action { get; set; }

        public string Details { get; set; }
    }
}
