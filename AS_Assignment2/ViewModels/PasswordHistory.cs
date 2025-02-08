using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class PasswordHistory
    {
        public int Id { get; set; }

        public int UserId { get; set; } // Foreign key to User

        [Required]
        [DataType(DataType.Password)]
        public string OldPassword { get; set; }

        [Required]
        public DateTime ChangeDate { get; set; }
    }
}
