namespace OrderFlowClase.API.Identity.Dto.Users
{
    public sealed record PasswordChangeRequest
    {
        public required string CurrentPassword { get; set; }
        public required string NewPassword { get; set; }
    }
}