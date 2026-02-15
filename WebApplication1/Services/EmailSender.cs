using System.Net;
using System.Net.Mail;

namespace WebApplication1.Services
{
    /// <summary>
    /// SMTP-based email sender. If Smtp:Host is not set, logs to console and skips sending (no exception).
    /// Do not pass sensitive data (passwords, exception messages, tokens in plain text) in subject or htmlBody
    /// when using SendEmailAsync; use dedicated methods (e.g. SendPasswordResetEmailAsync) for transactional emails.
    /// </summary>
    public class EmailSender : IEmailSender
    {
        private const string PasswordResetSubject = "Reset your Ace Job Agency password";
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        /// <summary>
        /// Sends a password-reset email using a fixed template. The callback URL is sent only to the intended recipient.
        /// This avoids passing sensitive data (reset link) through a generic channel and limits exposure to the recipient only.
        /// </summary>
        public async Task SendPasswordResetEmailAsync(string to, string callbackUrl)
        {
            var htmlBody = $"Please reset your password by clicking <a href=\"{WebUtility.HtmlEncode(callbackUrl)}\">this secure link</a>. The link will expire after a short time.";
            await SendEmailAsync(to, PasswordResetSubject, htmlBody);
        }

        public async Task SendEmailAsync(string to, string subject, string htmlBody)
        {
            var host = _configuration["Smtp:Host"];
            if (string.IsNullOrWhiteSpace(host))
            {
                _logger.LogWarning("SMTP is not configured (Smtp:Host missing). Email not sent to {To}, subject: {Subject}. Configure Smtp in appsettings.json to send emails.", to, subject);
                return;
            }

            var port = _configuration.GetValue<int>("Smtp:Port", 587);
            var userName = _configuration["Smtp:UserName"];
            var password = _configuration["Smtp:Password"];
            var fromEmail = _configuration["Smtp:FromEmail"] ?? userName ?? "noreply@acejobagency.com";
            var fromName = _configuration["Smtp:FromName"] ?? "Ace Job Agency";
            var enableSsl = _configuration.GetValue<bool>("Smtp:EnableSsl", true);

            try
            {
                using var client = new SmtpClient(host, port)
                {
                    EnableSsl = enableSsl,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false
                };
                if (!string.IsNullOrWhiteSpace(userName) && !string.IsNullOrWhiteSpace(password))
                    client.Credentials = new NetworkCredential(userName, password);

                using var message = new MailMessage
                {
                    From = new MailAddress(fromEmail, fromName),
                    Subject = subject,
                    Body = htmlBody,
                    IsBodyHtml = true
                };
                message.To.Add(to);

                await client.SendMailAsync(message);
                _logger.LogInformation("Email sent to {To}, subject: {Subject}.", to, subject);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {To}, subject: {Subject}.", to, subject);
                throw new InvalidOperationException("Failed to send email. Please try again later.");
            }
        }
    }
}
