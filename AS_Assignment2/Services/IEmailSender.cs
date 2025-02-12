using MimeKit;
using MailKit.Net.Smtp;
using AS_Assignment2.ViewModels;


namespace AS_Assignment2.Services
{
    public interface ICustomEmailSender
    {
        Task SendEmailAsync(Message message);
    }
}
