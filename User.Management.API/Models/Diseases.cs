using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace User.Management.API.Models
{
    public class Diseases
    {

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [JsonIgnore]
        public int Id { get; set; }

        [Required]
        public string Name { get; set; } = string.Empty;

        public string? Description { get; set; }

        public ICollection<UploadImages>? UploadImages { get; set; }
    }
}

