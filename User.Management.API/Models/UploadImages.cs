using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace User.Management.API.Models
{
    public class UploadImages
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [JsonIgnore]
        public int Id { get; set; }

        public byte[]? Image { get; set; }
        public string? Description{ get; set; }



        public int UserProfileId { get; set; }
        public UserProfile? UserProfile { get; set; }
        public int? DiseasesId { get; set; } // Foreign key to Disease
        public Diseases? Diseases { get; set; }
   
    }
}
