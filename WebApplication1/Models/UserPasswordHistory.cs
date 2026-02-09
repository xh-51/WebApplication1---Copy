using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    /// <summary>
    /// Stores the last N password hashes per user so we can reject password reuse.
    /// </summary>
    public class UserPasswordHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(450)]
        public string UserId { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    }
}
