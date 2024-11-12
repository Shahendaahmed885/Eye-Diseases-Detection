namespace User.Management.API.Models
{
    public class UserProfileResponse
{
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public double Height { get; set; }
        public double? Weight { get; set; }
        public string Gender { get; set; }
        public byte[] ProfilePhoto { get; set; }
    }
}
