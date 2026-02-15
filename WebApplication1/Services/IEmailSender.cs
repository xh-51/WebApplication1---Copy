namespace WebApplication1.Services
{
    /// <summary>
    /// Sends email (e.g. password reset). Uses SMTP when configured; otherwise logs and skips.
    /// </summary>
    public interface IEmailSender
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);

        /// <summary>
        /// Sends a password-reset email using a fixed template. The callback URL is sent only to the intended recipient (to).
        /// Use this instead of passing a constructed body to SendEmailAsync to avoid sensitive data exposure.
        /// </summary>
        Task SendPasswordResetEmailAsync(string to, string callbackUrl);
    }
}
