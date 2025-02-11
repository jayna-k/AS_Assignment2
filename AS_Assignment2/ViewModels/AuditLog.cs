using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AS_Assignment2.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public DateTime ActionTime { get; set; } = DateTime.UtcNow;

        [Required]
        [StringLength(100)]
        public string Action { get; set; }

        public string Details { get; set; }

        [ForeignKey(nameof(UserId))]
        public virtual UserClass User { get; set; }
    }
}
