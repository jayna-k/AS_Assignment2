using AS_Assignment2.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AS_Assignment2.ViewModels
{
    public class Session
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public string SessionToken { get; set; }

        [ForeignKey("UserId")]
        public virtual UserClass User { get; set; }
    }
}
