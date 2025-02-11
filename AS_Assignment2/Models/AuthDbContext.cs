using AS_Assignment2.ViewModels;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace AS_Assignment2.Models
{
    public class AuthDbContext : IdentityDbContext<UserClass>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options)
            : base(options)
        {
        }

        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<LoginAttempt> LoginAttempts { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<AuditLog>()
                .HasOne(al => al.User)
                .WithMany()
                .HasForeignKey(al => al.UserId);

            builder.Entity<LoginAttempt>()
                .HasOne(la => la.User)
                .WithMany()
                .HasForeignKey(la => la.UserId);
        }
    }
}


