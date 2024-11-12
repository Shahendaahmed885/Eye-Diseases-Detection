namespace User.Management.API.Models
{
    public class ApplicationUser : IdentityUser
    {
        public DateTime? RowFactorTokenExpir { get; set; }
        public string? RowFactorToken { get; set; }
    }
}
