using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AS_Assignment2.Models
{
    public class LoginAttempt
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public DateTime AttemptTime { get; set; } = DateTime.UtcNow;

        [Required]
        public bool IsSuccessful { get; set; }

        [StringLength(45)]
        public string IPAddress { get; set; }

        [ForeignKey(nameof(UserId))]
        public virtual UserClass User { get; set; }
    }
}
