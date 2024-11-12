using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;
using User.Management.API.Models.Authentication.SignUp;

namespace User.Management.API.Models
{
    public class UserProfile
    {


        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [JsonIgnore]
        public int Id { get; set; }



        [Required]
        public string? FirstName { get; set; }

        [Required]
        public string? LastName { get; set; }


        public DateTime DateOfBirth { get; set; }
        public double Height { get; set; }
        public double Weight { get; set; }
        public string? Gender { get; set; }

        public byte[]? ProfilePhoto { get; set; }
        public ICollection<MedicalHistory>? MedicalHistories { get; set; }

        public ICollection<UploadImages>? UploadImages { get; set; }





       
    }

    }


