using AngularAuthWebAPI.Models.Auth;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthWebAPI.Context
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<AuthUser> AuthUsers { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AuthUser>().ToTable("AuthUsers");
        }
    }
}
