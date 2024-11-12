

using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace User.Management.API.Models
{
    public class MedicalHistory
    {
       

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [JsonIgnore]
        public int Id { get; set; }

        public string? Allergies { get; set; }
        public string? ChronicConditions { get; set; }
        public string? Medications { get; set; }
        public string? Surgeries { get; set; }
        public string? FamilyHistory { get; set; }
        private DateTime? _lastCheckupDate;

        [DataType(DataType.Date)]
        [Display(Name = "Last Checkup Date")]
        public DateTime? LastCheckupDate
        {
            get => _lastCheckupDate;
            set
            {
                if (value > DateTime.Now)
                    throw new ArgumentOutOfRangeException(nameof(LastCheckupDate), "Checkup date cannot be in the future.");
                _lastCheckupDate = value;
            }
        }

        public string? AdditionalNotes { get; set; }


        public TimeSpan? TimeSinceLastCheckup()
        {
           return _lastCheckupDate.HasValue ? DateTime.Now - _lastCheckupDate.Value : null;
        }

        public string GetSummary()
        {
            return $"Allergies: {Allergies ?? "None"}, Chronic Conditions: {ChronicConditions ?? "None"}, " +
                   $"Medications: {Medications ?? "None"}, Surgeries: {Surgeries ?? "None"}, " +
                   $"Family History: {FamilyHistory ?? "None"}, Last Checkup: {LastCheckupDate:yyyy-MM-dd}, " +
                   $"Additional Notes: {AdditionalNotes ?? "None"}";
        }


        public int UserProfileId { get; set; }
        public UserProfile? UserProfile { get; set; }
    }

}
