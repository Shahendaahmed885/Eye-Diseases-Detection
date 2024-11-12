using Microsoft.EntityFrameworkCore;

namespace User.Management.API.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage ="User name is required")]
        [Key]
        public string? UserName { get; set; }


        [EmailAddress]
        [Required(ErrorMessage ="Email is required")]
        public string? Email { get; set; }


        [MinLength(6, ErrorMessage = "Password must be at least 6 ,maximum 20 characters")]
        [Required(ErrorMessage = "Password is required")]

      public string? Password { get; set; }


        



    }
}
