using System;

namespace AuthApp.Services
{
    public interface IAuthenticationService
    {
        string GneratePassword(byte[] secredKey, DateTime time);

        string GneratePassword(byte[] secredKey, DateTime time, int length);

        bool ValidatePassword(string providedPassword, DateTime currentTime, TimeSpan validityPeriod);
    }
}