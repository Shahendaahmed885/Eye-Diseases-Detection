namespace Models
{
    public class UploadImageRequest
    {
        public IList<IFormFile>? Images { get; set; }
        public string? Description { get; set; }

    }
}
