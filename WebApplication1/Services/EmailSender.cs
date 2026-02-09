using System.Net;
using System.Net.Mail;

namespace WebApplication1.Services
{
    /// <summary>
    /// SMTP-based email sender. If Smtp:Host is not set, logs to console and skips sending (no exception).
    /// </summary>
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
        {
            _configuration = configuration;
            _logger = logger;
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
                throw;
            }
        }
    }
}
