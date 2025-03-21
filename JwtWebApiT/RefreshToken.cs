namespace JwtWebApiT
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public DateTime ExpiredDate {  get; set; }

        
    }
}
