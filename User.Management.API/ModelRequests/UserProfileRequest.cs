namespace User.Management.API.ModelRequests
{
    public class UserProfileRequest
    {


        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public double Height { get; set; }
        public double? Weight { get; set; }
        public string? Gender { get; set; }
        public IFormFile? ProfilePhoto { get; set; }
        
    }
}
