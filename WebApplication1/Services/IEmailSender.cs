namespace WebApplication1.Services
{
    /// <summary>
    /// Sends email (e.g. password reset). Uses SMTP when configured; otherwise logs and skips.
    /// </summary>
    public interface IEmailSender
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);
    }
}
