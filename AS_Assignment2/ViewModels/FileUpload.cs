using System.ComponentModel.DataAnnotations;

namespace AS_Assignment2.ViewModels
{
    public class FileUpload
    {
        public int Id { get; set; }

        public int UserId { get; set; } // Foreign key to User

        [Required]
        [DataType(DataType.Upload)]
        public IFormFile File { get; set; }

        [Required]
        public DateTime UploadDate { get; set; }

        public string FilePath { get; set; }
    }
}
