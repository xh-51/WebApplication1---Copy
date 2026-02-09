using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<UserPasswordHistory> UserPasswordHistories { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Ensure Email is unique (Identity already handles this, but we can add additional constraints)
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.HasIndex(e => e.Email)
                    .IsUnique();
            });

            // Configure AuditLog
            builder.Entity<AuditLog>(entity =>
            {
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.Timestamp);
                entity.HasIndex(e => e.SessionId);
            });

            // Password history for "cannot reuse last 2 passwords"
            builder.Entity<UserPasswordHistory>(entity =>
            {
                entity.HasIndex(e => e.UserId);
            });
        }
    }
}
