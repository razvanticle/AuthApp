using System;

namespace AuthApp.Services
{
    public interface IAuthenticationService
    {
        string GneratePassword(string secredKey, DateTime time);

        bool ValidatePassword(string providedPassword, DateTime currentTime, TimeSpan validityPeriod);
    }
}