using System;

namespace AuthApp.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        public string GneratePassword(string secredKey, DateTime time)
        {
            throw new NotImplementedException();
        }

        public bool ValidatePassword(string providedPassword, DateTime currentTime, TimeSpan validityPeriod)
        {
            throw new NotImplementedException();
        }
    }
}
