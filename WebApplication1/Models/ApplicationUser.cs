using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        public string Gender { get; set; } = string.Empty;

        // NRIC is encrypted before saving to database
        [Required]
        [Display(Name = "NRIC")]
        public string NRIC { get; set; } = string.Empty; // Stored encrypted

        [Required]
        [Display(Name = "Date of Birth")]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }

        [Display(Name = "Resume File Name")]
        public string? ResumeFileName { get; set; }

        [Display(Name = "Resume File Path")]
        public string? ResumeFilePath { get; set; }

        [Display(Name = "Who Am I")]
        public string? WhoAmI { get; set; } // Allows all special characters

        // Password policy tracking
        [Display(Name = "Last Password Change")]
        public DateTime? LastPasswordChangeDate { get; set; }

        [Display(Name = "Password History Count")]
        public int PasswordHistoryCount { get; set; } = 0;
    }
}
