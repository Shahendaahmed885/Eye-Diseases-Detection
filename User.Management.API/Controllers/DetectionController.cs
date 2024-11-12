
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing.Constraints;
using Microsoft.EntityFrameworkCore;
using Models;
using System.Security.Claims;
using User.Management.API.ModelRequests;
using User.Management.API.Models;
using User.Management.Service.Models;
using static System.Net.Mime.MediaTypeNames;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DetectionController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DetectionController> _logger;
        public DetectionController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole>
            roleManager, IConfiguration configuration, SignInManager<IdentityUser> signInManager, ApplicationDbContext context, ILogger<DetectionController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
        }
        [HttpPost("UploadImages")]
        public async Task<IActionResult> UploadImage(int userProfileId, [FromForm] UploadImageRequest request)
        {
            if (request == null || request.Images == null || request.Images.Count == 0)
            {
                return BadRequest("No images provided.");

            }

            var userProfile = await _context.UserProfiles.FindAsync(userProfileId);
            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = "User profile not found." });
            }

            var uploadImages = new List<UploadImages>();
            var results = new List<object>();

           
            foreach (var image in request.Images)
            {
                using var memoryStream = new MemoryStream();
                await image.CopyToAsync(memoryStream);
                var imageBytes = memoryStream.ToArray();

          
                var detectedDisease = await DetectDiseaseFromImage(imageBytes);

           
                results.Add(new
                {
           
                    DiseaseName = detectedDisease.Name,
                    Description = detectedDisease.Description
                });

                
                var uploadImage = new UploadImages
                {
                    Image = imageBytes,
                    Description = request.Description,
                    UserProfileId = userProfileId 
                };

                uploadImages.Add(uploadImage);
            }

            try
            {
                // Add the list of images to the database if needed
                await _context.uploadImages.AddRangeAsync(uploadImages);
                await _context.SaveChangesAsync();

                return Ok(new { Status = "Success", Message = $"{uploadImages.Count} images uploaded successfully.", Results = results });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading images.");
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = $"Failed to upload images: {ex.Message}" });
            }
        }

        private async Task<Diseases> DetectDiseaseFromImage(byte[] imageBytes)
        {
            //  implement logic to detect the disease
            //  this could involve calling a machine learning model
            // we will return a dummy disease for demonstration

            //  ML model or some logic to determine the disease
            return new Diseases
            {
                Name = "Cataracts", 
                Description = "Cataracts are a clouding of the lens of the eye that affects vision." 
            };
        }

        [HttpGet("UploadedImages/{userProfileId}")]
        public async Task<IActionResult> GetUploadedImages(int userProfileId)
        {
            
            var userProfile = await _context.UserProfiles.FindAsync(userProfileId);
            if (userProfile == null)
            {
                return NotFound(new { Status = "Error", Message = "User profile not found." });
            }

           
            var uploadedImages = await _context.uploadImages
                .Where(ui => ui.UserProfileId == userProfileId)
                .ToListAsync();

           
            if (uploadedImages == null || !uploadedImages.Any())
            {
                return NotFound(new { Status = "Error", Message = "No images found for this user profile." });
            }

     
            var results = new List<object>();
            foreach (var image in uploadedImages)
            {
                // Here, you might want to call the disease detection logic if you haven't stored it
                var detectedDisease = await DetectDiseaseFromImage(image.Image); // Assuming want to use the stored image bytes for detection

                results.Add(new
                {
                    ImageId = image.Id, 
                    Description = image.Description,
                    ImageBase64 = Convert.ToBase64String(image.Image), // Convert image to base64 string for display
                    DiseaseName = detectedDisease.Name,
                    DiseaseDescription = detectedDisease.Description
                });
            }

            return Ok(new
            {
                Status = "Success",
                Images = results
            });
        }

    }
}













