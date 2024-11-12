using System.Collections.Generic;

namespace User.Management.API.ModelRequests
{
    public class MedicalHistoryRequest
    {
        public string? Allergies { get; set; }
        public string? ChronicConditions { get; set; }
        public string? Medications { get; set; }
        public string? Surgeries { get; set; }
        public string? FamilyHistory { get; set; }
        public DateTime? LastCheckupDate { get; set; }
        public string? AdditionalNotes { get; set; }


    }
}
