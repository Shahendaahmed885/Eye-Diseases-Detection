

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Management.API.Models.Authentication.SignUp;

namespace User.Management.API.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }
      public DbSet<UserProfile> UserProfiles { get; set; }
      public DbSet<MedicalHistory> MedicalHistories { get; set; }
      public DbSet<UploadImages>uploadImages { get; set; }
      public DbSet<Diseases> Diseases { get; set; }

      
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
           SeedRoles(modelBuilder);
        


            modelBuilder.Entity<UserProfile>()
            .HasMany(u => u.MedicalHistories)
            .WithOne(m => m.UserProfile)
            .HasForeignKey(m => m.Id)
            .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserProfile>()
                .HasMany(u => u.UploadImages)
                .WithOne(ui => ui.UserProfile)
                .HasForeignKey(ui => ui.UserProfileId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UploadImages>()
            .HasOne(ui => ui.Diseases)
            .WithMany(d => d.UploadImages)
            .HasForeignKey(ui => ui.DiseasesId)
            .OnDelete(DeleteBehavior.Cascade);

          

            modelBuilder.Entity<Diseases>().HasData(
        new Diseases { Id = 1, Name = "Bulging Eyes", Description = "Protrusion of one or both eyes from the eye socket." },
        new Diseases { Id = 2, Name = "Cataracts", Description = "Clouding of the eye's lens, leading to decreased vision." },
        new Diseases { Id = 3, Name = "Crossed-Eyes", Description = "A condition where the eyes do not align properly." },
        new Diseases { Id = 4, Name = "Glaucoma", Description = "A group of eye conditions that damage the optic nerve." },
        new Diseases { Id = 5, Name = "Uveitis", Description = "Inflammation of the uvea, the middle layer of the eye." }
    );


        }
        private void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User" }



                );
        }




    }   
}
