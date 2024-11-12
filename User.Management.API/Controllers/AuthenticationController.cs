using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Web.Mvc.Controls;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.SERVICE;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using Microsoft.EntityFrameworkCore;
using User.Management.API.ModelRequests;
using Models;


namespace User.Management.API.Controllers
{


    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DetectionController> _logger;
        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole>
            roleManager, IEmailService emailService, IConfiguration configuration, SignInManager<ApplicationUser> signInManager, ApplicationDbContext context, ILogger<DetectionController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
        }


        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromForm] string UserName, [FromForm] string Email, [FromForm] string Password, [FromQuery] string Role)
        {
            if (string.IsNullOrWhiteSpace(UserName))
            {
                return BadRequest(new Response { Status = "Error", Message = "UserName is required." });
            }

            if (string.IsNullOrWhiteSpace(Email))
            {
                return BadRequest(new Response { Status = "Error", Message = "Email is required." });
            }

            if (!IsValidPassword(Password))
            {
                return BadRequest(new Response
                {
                    Status = "Error",
                    Message = "Password is required and must be between 6 and 20 characters long ," +
                    " include at least one capital letter , number and one special character (@#$%&!)."
                });
            }

            if (string.IsNullOrWhiteSpace(Role))
            {
                return BadRequest(new Response { Status = "Error", Message = "Role is required." });
            }

            var userExist = await _userManager.FindByEmailAsync(Email);
            if (userExist != null)
            {
                return BadRequest(new Response { Status = "Error", Message = "User already exists." });
            }

            var user = new ApplicationUser
            {
                UserName = UserName,
                Email = Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true
            };

            if (await _roleManager.RoleExistsAsync(Role))
            {
                var result = await _userManager.CreateAsync(user, Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = $"User creation failed, Please try again." });
                }


                await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Email, user.Email));

                await _userManager.AddToRoleAsync(user, Role);

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new[] { user.Email }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return Ok(new Response { Status = "Success", Message = $"User created & Email sent to {user.Email} successfully." });
            }
            else
            {
                return BadRequest(new Response { Status = "Error", Message = "This role does not exist." });
            }


        }
        private bool IsValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6 || password.Length > 20)
                return false;

            bool hasUpperCase = password.Any(char.IsUpper);
            bool hasSpecialChar = password.Any(ch => "@#$%&!".Contains(ch));

            return hasUpperCase && hasSpecialChar;
        }







        [HttpGet("ConfirmEmail")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "success", Message = "Email Verified Successfully" });
                }

            }

            return NotFound(new Response { Status = "Error", Message = "User not found." });



        }






        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromForm] LoginModel loginModel)
        {
            if (loginModel == null)
            {
                return BadRequest(new { Status = "Error", Message = "Login model cannot be null." });
            }

            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                return Unauthorized(new { Status = "Error", Message = "Invalid username or password." });
            }

            // If TwoFactorEnabled is true, handle the OTP process
            if (user.TwoFactorEnabled)
            {
                // Sign out the user to reset any previous sessions
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

                // Generate OTP and send it via email
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email }, "OTP Confirmation", token);
                _emailService.SendEmail(message);

                // Return the JWT token for the login process (before OTP verification)
                var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email)

        };

                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = GenerateJwtToken2(authClaims);
                var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                return Ok(new { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}", token = tokenString });
            }

            // If TwoFactorEnabled is false, authenticate normally and return JWT token
            var normalAuthClaims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.NameIdentifier, user.Id)
    };

            var normalUserRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in normalUserRoles)
            {
                normalAuthClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var normalJwtToken = GenerateJwtToken2(normalAuthClaims);
            var normalTokenString = new JwtSecurityTokenHandler().WriteToken(normalJwtToken);

            return Ok(new { Status = "Success", token = normalTokenString });
        }

        private JwtSecurityToken GenerateJwtToken2(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            return new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(8),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }




        [HttpPost("VerifyOTP")]
        public async Task<IActionResult> VerifyOTP([FromBody] OTPVerificationModel otpModel)
        {
            // Extract the JWT token from the Authorization header
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized(new { Status = "Error", Message = "Token is missing." });
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var jwtToken = tokenHandler.ReadJwtToken(token);

              
                var usernameClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                if (string.IsNullOrEmpty(usernameClaim))
                {
                    return Unauthorized(new { Status = "Error", Message = "Invalid token." });
                }

                var user = await _userManager.FindByNameAsync(usernameClaim);
                if (user == null)
                {
                    return Unauthorized(new { Status = "Error", Message = "User not found." });
                }

                // Validate OTP
                var signIn = await _signInManager.TwoFactorSignInAsync("Email", otpModel.Code, false, false);
                if (signIn.Succeeded)
                {
                    // OTP is valid, generate new JWT token
                    var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtTokenNew = GenerateJwtToken2(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtTokenNew),
                        expiration = jwtTokenNew.ValidTo
                    });
                }

                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "Invalid OTP" });
            }
            catch (Exception ex)
            {
                return Unauthorized(new { Status = "Error", Message = "Invalid token.", Exception = ex.Message });
            }
        }



        //-------------------------------------------------------------------------------------------------

        //USERPROFILE











        [HttpPost("CreateUserProfile")]
        public async Task<IActionResult> CreateUserProfile([FromForm] UserProfileRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.FirstName) ||
            string.IsNullOrWhiteSpace(request.LastName) ||
            request.DateOfBirth == default ||
            request.Height <= 0 ||
            request.Weight < 0 ||
            string.IsNullOrWhiteSpace(request.Gender))
            {
                return BadRequest(new { Status = "Error", Message = "Invalid user profile data. All fields are required." });
            }


            var existingProfile = await _context.UserProfiles
            .FirstOrDefaultAsync(up =>
          up.FirstName == request.FirstName &&
          up.LastName == request.LastName &&
          up.DateOfBirth == request.DateOfBirth);

            if (existingProfile != null)
            {
                return Conflict(new { Status = "Error", Message = "A user profile with the same details already exists." });
            }


            byte[]? profilePhotoData = null;
            if (request.ProfilePhoto != null && request.ProfilePhoto.Length > 0)
            {
                using (var memoryStream = new MemoryStream())
                {
                    await request.ProfilePhoto.CopyToAsync(memoryStream);
                    profilePhotoData = memoryStream.ToArray();
                }
            }

            var userProfile = new UserProfile
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                DateOfBirth = request.DateOfBirth,
                Height = request.Height,
                Weight = request.Weight ?? 0,
                Gender = request.Gender,
                ProfilePhoto = profilePhotoData
            };

            try
            {
                await _context.UserProfiles.AddAsync(userProfile);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = $"Failed to create user profile: {ex.Message}" });
            }

            return Ok(new { Status = "Success", Message = "User profile created successfully." });
        }



        [HttpGet("UserProfile/{id}")]
        public async Task<IActionResult> GetUserProfile(int id)
        {
            var userProfile = await _context.UserProfiles
                .SingleOrDefaultAsync(up => up.Id == id);

            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = $"User profile with ID '{id}' does not exist." });
            }


            var userProfileResponse = new UserProfileResponse
            {
                Id = userProfile.Id,
                FirstName = userProfile.FirstName!,
                LastName = userProfile.LastName!,
                DateOfBirth = userProfile.DateOfBirth,
                Height = userProfile.Height,
                Weight = userProfile.Weight,
                Gender = userProfile.Gender!,
                ProfilePhoto = userProfile.ProfilePhoto!
            };

            return Ok(new { Status = "Success", Data = userProfileResponse });
        }








        [HttpPut("UpdateUserProfile/{id}")]
        public async Task<IActionResult> UpdateUserProfile(int id, [FromForm] UserProfileRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.FirstName) ||
                string.IsNullOrWhiteSpace(request.LastName) ||
                request.DateOfBirth == default ||
                request.Height <= 0 ||
                request.Weight < 0 ||
                string.IsNullOrWhiteSpace(request.Gender))
            {
                return BadRequest(new { Status = "Error", Message = "Invalid user profile data. All fields are required." });
            }

            var userProfile = await _context.UserProfiles.FindAsync(id);
            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = "User profile not found." });
            }


            userProfile.FirstName = request.FirstName ?? userProfile.FirstName;
            userProfile.LastName = request.LastName ?? userProfile.LastName;
            userProfile.DateOfBirth = request.DateOfBirth;
            userProfile.Height = request.Height;
            userProfile.Weight = (double)request.Weight!;
            userProfile.Gender = request.Gender;

            if (request.ProfilePhoto != null && request.ProfilePhoto.Length > 0)
            {
                userProfile.ProfilePhoto = await ConvertToByteArrayAsync(request.ProfilePhoto);
            }


            await _context.SaveChangesAsync();

            return Ok(new { Status = "Success", Message = "User profile updated successfully." });
        }


        private async Task<byte[]> ConvertToByteArrayAsync(IFormFile file)
        {
            using var memoryStream = new MemoryStream();
            await file.CopyToAsync(memoryStream);
            return memoryStream.ToArray();
        }






        [HttpDelete("DeleteUserProfile/{id}")]
        public async Task<IActionResult> DeleteUserProfile(int id)
        {

            var userProfile = await _context.UserProfiles.SingleOrDefaultAsync(up => up.Id == id);

            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = $"User profile with id '{id}' does not exist." });
            }

            try
            {

                _context.UserProfiles.Remove(userProfile);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = $"Failed to delete user profile: {ex.Message}" });
            }


            return Ok(new { Status = "Success", Message = "User profile deleted successfully." });
        }





        //------------------------------------------------------------------------------------------------------------------------

        //MEDICALHISTORY





        [HttpPost("MedicalHistory/{userProfileId}")]
        public async Task<IActionResult> CreateMedicalHistory(int userProfileId, [FromForm] string allergies, [FromForm] string chronicConditions, [FromForm] string medications, [FromForm] string surgeries,
            [FromForm] string familyHistory, [FromForm] DateTime? lastCheckupDate, [FromForm] string additionalNotes)
        {
            // Validate the incoming data
            if (string.IsNullOrWhiteSpace(allergies) ||
                string.IsNullOrWhiteSpace(chronicConditions) ||
                string.IsNullOrWhiteSpace(medications) ||
                string.IsNullOrWhiteSpace(surgeries) ||
                string.IsNullOrWhiteSpace(familyHistory) ||
                string.IsNullOrWhiteSpace(additionalNotes))
            {
                return BadRequest("Invalid medical history data, All fields are required ");
            }


            DateTime? checkupDate = lastCheckupDate;

            var userProfile = await _context.UserProfiles.FindAsync(userProfileId);
            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = "User profile not found." });
            }


            var existingMedicalHistory = await _context.MedicalHistories
                .FirstOrDefaultAsync(mh => mh.UserProfileId == userProfileId);

            if (existingMedicalHistory != null)
            {
                return Conflict(new
                {
                    Status = "Error",
                    Message = "Medical history already exists for this user profile."
                });
            }


            var medicalHistory = new MedicalHistory
            {
                Id = userProfileId,
                Allergies = allergies,
                ChronicConditions = chronicConditions,
                Medications = medications,
                Surgeries = surgeries,
                FamilyHistory = familyHistory,
                LastCheckupDate = checkupDate ?? DateTime.Now,
                AdditionalNotes = additionalNotes,
                UserProfileId = userProfileId
            };

            try
            {
                await _context.MedicalHistories.AddAsync(medicalHistory);
                await _context.SaveChangesAsync();

                return CreatedAtAction(nameof(GetMedicalHistory), new { userProfileId = medicalHistory.UserProfileId }, new
                {
                    Status = "Success",
                    Message = "Medical history created successfully."
                });
            }
            catch (DbUpdateException dbEx)
            {
                var innerException = dbEx.InnerException?.Message ?? "No inner exception";
                return StatusCode(StatusCodes.Status500InternalServerError, $"Database error: {innerException}");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Internal server error: {ex.Message}");
            }
        }







        [HttpGet("MedicalHistory/{userProfileId}")]
        public async Task<IActionResult> GetMedicalHistory(int userProfileId)
        {

            var userProfile = await _context.UserProfiles.FindAsync(userProfileId);
            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = "User profile not found." });
            }

            var medicalHistory = await _context.MedicalHistories
                .FirstOrDefaultAsync(mh => mh.UserProfileId == userProfileId);

            if (medicalHistory == null)
            {
                return NotFound(new { Status = "Error", Message = "No medical history found for this user profile." });
            }

            return Ok(new
            {
                Status = "Success",
                MedicalHistory = new
                {
                    medicalHistory.Allergies,
                    medicalHistory.ChronicConditions,
                    medicalHistory.Medications,
                    medicalHistory.Surgeries,
                    medicalHistory.FamilyHistory,
                    LastCheckupDate = medicalHistory.LastCheckupDate?.ToString("yyyy-MM-dd"),
                    medicalHistory.AdditionalNotes,

                }
            });
        }








        [HttpPut("UpdateMedicalHistory/{userProfileId}")]
        public async Task<IActionResult> UpdateMedicalHistory(
            int userProfileId,
            [FromForm] string allergies,
            [FromForm] string chronicConditions,
            [FromForm] string medications,
            [FromForm] string surgeries,
            [FromForm] string familyHistory,
            [FromForm] DateTime? lastCheckupDate, // Nullable DateTime
            [FromForm] string additionalNotes)
        {
            var medicalHistory = await _context.MedicalHistories.FindAsync(userProfileId);
            if (medicalHistory == null)
            {
                return NotFound(new { Status = "Error", Message = "Medical history not found." });
            }

            medicalHistory.Allergies = string.IsNullOrWhiteSpace(allergies) ? medicalHistory.Allergies : allergies;
            medicalHistory.ChronicConditions = string.IsNullOrWhiteSpace(chronicConditions) ? medicalHistory.ChronicConditions : chronicConditions;
            medicalHistory.Medications = string.IsNullOrWhiteSpace(medications) ? medicalHistory.Medications : medications;
            medicalHistory.Surgeries = string.IsNullOrWhiteSpace(surgeries) ? medicalHistory.Surgeries : surgeries;
            medicalHistory.FamilyHistory = string.IsNullOrWhiteSpace(familyHistory) ? medicalHistory.FamilyHistory : familyHistory;

            // If no date is provided, keep the existing value
            medicalHistory.LastCheckupDate = lastCheckupDate ?? medicalHistory.LastCheckupDate;

            medicalHistory.AdditionalNotes = string.IsNullOrWhiteSpace(additionalNotes) ? medicalHistory.AdditionalNotes : additionalNotes;

            await _context.SaveChangesAsync();

            return Ok(new { Status = "Success", Message = "Medical history updated successfully." });
        }




        //--------------------------------------------------------------------------------------------------------------------------------------

        //PASSWORD







    [HttpPost("ForgotPassword")]
       [AllowAnonymous]

      public async Task<IActionResult> ForgotPassword()
      {





    // Extract the JWT token from the Authorization header
    var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");


    if (string.IsNullOrEmpty(token))
    {
        return Unauthorized(new { Status = "Error", Message = "Token is missing." });
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
        var jwtToken = tokenHandler.ReadJwtToken(token);

        // Extract the email from the JWT token claims
        var emailClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
        
        // If email claim is not found in the default claim type, try other claim names like "email"
        if (string.IsNullOrEmpty(emailClaim))
        {
            emailClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
        }

        if (string.IsNullOrEmpty(emailClaim))
        {
            return Unauthorized(new { Status = "Error", Message = "Email not found in token." });
        }

        var user = await _userManager.FindByEmailAsync(emailClaim);
        if (user != null)
        {
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action(nameof(Resetpassword), "Authentication", new { token = resetToken, email = user.Email }, Request.Scheme);

            var message = new Message(new string[] { user.Email }, "Forgot Password email link", resetLink);
            _emailService.SendEmail(message);

            return Ok(new Response { Status = "Success", Message = $"Password reset link sent to {user.Email}. Please check your email and click the link to reset your password." });
        }

        return BadRequest(new Response { Status = "Error", Message = "User not found." });
    }


    catch (Exception ex)
    {
        return Unauthorized(new { Status = "Error", Message = "Invalid token.", Exception = ex.Message });




    }
}








        [HttpGet("ResetPassword")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> Resetpassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new
            {
                model

            });
        }



        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));
            return token;

        }





        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromForm] string password, [FromForm] string confirmPassword, [FromForm] string token)
        {
            //  Authorization header
            var tokenFromHeader = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (string.IsNullOrEmpty(tokenFromHeader))
            {
                return Unauthorized(new { Status = "Error", Message = "Token is missing." });
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var jwtToken = tokenHandler.ReadJwtToken(tokenFromHeader);

                // Extract email from the JWT token claims
                var emailClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                if (string.IsNullOrEmpty(emailClaim))
                {
                    return Unauthorized(new { Status = "Error", Message = "Email not found in token." });
                }

                var user = await _userManager.FindByEmailAsync(emailClaim);
                if (user == null)
                {
                    return BadRequest(new Response { Status = "Error", Message = "User not found." });
                }

                // Validate password
                if (!IsValidPassword2(password))
                {
                    return BadRequest(new Response
                    {
                        Status = "Error",
                        Message = "Password must be between 6 and 20 characters long, include at least one capital letter, one number, and one special character (@#$%&!)."
                    });
                }

                if (password != confirmPassword)
                {
                    ModelState.AddModelError("ConfirmPassword", "Passwords do not match.");
                    return BadRequest(ModelState);
                }

                var resetPassResult = await _userManager.ResetPasswordAsync(user, token, password);
                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        if (error.Code == "InvalidToken")
                        {
                            return BadRequest(new Response { Status = "Error", Message = "The token has expired or is invalid." });
                        }
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return BadRequest(ModelState);
                }

                return Ok(new Response { Status = "Success", Message = "Password has been changed successfully." });
            }
            catch (Exception ex)
            {
                return Unauthorized(new { Status = "Error", Message = "Invalid token.", Exception = ex.Message });
            }
        }




        private bool IsValidPassword2(string password)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 6 || password.Length > 20)
                return false;

            bool hasUpperCase = password.Any(char.IsUpper);
            bool hasSpecialChar = password.Any(ch => "@#$%&!".Contains(ch));

            return hasUpperCase && hasSpecialChar;
        }









        //----------------------------------------------------------------------------------------------------------------------------------------------------------


        [HttpGet("UserInfo")]
        public async Task<IActionResult> GetUserInfoFromToken()
        {
            // Extract the JWT token from the Authorization header
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized(new { Status = "Error", Message = "Token is missing." });
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var jwtToken = tokenHandler.ReadJwtToken(token);

                // Extract the user information (e.g., username, user ID) from the JWT token claims
                var usernameClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                if (string.IsNullOrEmpty(usernameClaim))
                {
                    return Unauthorized(new { Status = "Error", Message = "Invalid token." });
                }

                var user = await _userManager.FindByNameAsync(usernameClaim);
                if (user == null)
                {
                    return Unauthorized(new { Status = "Error", Message = "User not found." });
                }

              
                var userInfo = new
                {
                    user.UserName,
                    user.Email,
                    Roles = await _userManager.GetRolesAsync(user)
                };

                return Ok(new { Status = "Success", UserInfo = userInfo });
            }
            catch (Exception ex)
            {
                return Unauthorized(new { Status = "Error", Message = "Invalid token.", Exception = ex.Message });
            }
        }




        //-------------------------------------------------------------------------------------------------------------------------------------------------------


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync(); 
            return Ok(new { Status = "Success", Message = "Logged out successfully." });
        }





 }

    public class OTPVerificationModel
    {
        public string Code { get; set; }
    }




}






