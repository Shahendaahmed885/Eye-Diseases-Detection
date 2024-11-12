

using User.Management.Service.Models;

namespace User.Management.Service.SERVICE
{
   public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
