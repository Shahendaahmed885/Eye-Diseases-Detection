using MailKit.Net.Smtp;
using MimeKit;
using User.Management.Service.Models;
using SmtpClient = MailKit.Net.Smtp.SmtpClient;

namespace User.Management.Service.SERVICE
{
  public class EmailService : IEmailService
    {
      private readonly EmailConfiguration _emailconfig;
      public EmailService(EmailConfiguration emailconfig)=>_emailconfig = emailconfig;
      
        public void SendEmail(Message message)
        {
           var emailMessage = CreateEmailMessage(message);
           Send(emailMessage);

        }

        public void SendEmail(string? email, Message message)
        {
            throw new NotImplementedException();
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", _emailconfig.From));
            emailMessage.To .AddRange(message.To);  
            emailMessage.Subject= message.Subject;
            emailMessage.Body= new TextPart(MimeKit.Text.TextFormat.Text) { Text=message.Content };

            return emailMessage;

        }  
        private void Send(MimeMessage emailMessage)
        {
           using var client = new SmtpClient();
            try
            {
                client.Connect(_emailconfig.SmtpServer, _emailconfig.Port, MailKit.Security.SecureSocketOptions.StartTls);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailconfig.UserName, _emailconfig.Password);
                client.Send(emailMessage);
                
            }
            catch
            {
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
             
            }
        }
    }
}
