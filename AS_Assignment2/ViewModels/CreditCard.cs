using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class CreditCard
    {
        public int Id { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        public string CardNumber { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string CardHolderName { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime ExpirationDate { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string CVV { get; set; }

        public int UserId { get; set; }
    }
}
