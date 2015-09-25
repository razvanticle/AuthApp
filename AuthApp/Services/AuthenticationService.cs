using System;

namespace AuthApp.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        public AuthenticationService(IOtpGenerator otpGenerator)
        {
            this.otpGenerator = otpGenerator;
        }

        public string GneratePassword(byte[] secredKey, DateTime time)
        {
            return GneratePassword(secredKey, time, DefaultPasswordLength);
        }

        public string GneratePassword(byte[] secredKey, DateTime time, int length)
        {
            var span = time.ToUniversalTime() - unixTime;
            var steps = (int) (span.TotalSeconds/TimeStep);

            return otpGenerator.GenerateOtp(steps, secredKey, length);
        }

        public bool ValidatePassword(string providedPassword, DateTime currentTime, TimeSpan validityPeriod)
        {
            throw new NotImplementedException();
        }

        private readonly int DefaultPasswordLength = 6;
        private readonly int TimeStep = 30;
        private readonly DateTime unixTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly IOtpGenerator otpGenerator;
    }
}