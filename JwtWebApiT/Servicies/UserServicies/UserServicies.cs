using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Security.Claims;

namespace JwtWebApiT.Servicies.UserServicies
{
    public class UserServicies : IUserServicie
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public UserServicies(IHttpContextAccessor httpContextAcessor) {
            _httpContextAccessor = httpContextAcessor;        
        }
        public string GetMyName()
        {
            var result = string.Empty;

            if (_httpContextAccessor.HttpContext != null)
            {
                result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return result;      
        }
    }
}
