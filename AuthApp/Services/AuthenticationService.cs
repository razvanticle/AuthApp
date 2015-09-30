using System;

namespace AuthApp.Services
{
    /// <summary>
    ///     Generates one-time passwords based on the current time and a secret key TOTP algorithm.
    ///     https://www.ietf.org/rfc/rfc6238.txt
    /// </summary>
    public class AuthenticationService : IAuthenticationService
    {
        /// <summary>
        ///     Initializes a new instance of AuthenticationService class.
        /// </summary>
        /// <param name="otpGenerator">The one-time password generator.</param>
        public AuthenticationService(IOtpGenerator otpGenerator)
        {
            this.otpGenerator = otpGenerator;
        }

        /// <summary>
        ///     Generates one-time passwords based on the given time and secret key.
        /// </summary>
        /// <param name="secredKey">The secret key.</param>
        /// <param name="time">The time for which to generate the password.</param>
        /// <returns>The one-time generated password.</returns>
        public string GneratePassword(byte[] secredKey, DateTime time)
        {
            return GneratePassword(secredKey, time, DefaultPasswordLength);
        }

        /// <summary>
        ///     Generates one-time passwords based on the given time and secret key.
        /// </summary>
        /// <param name="secredKey">The secret key.</param>
        /// <param name="time">The time for which to generate the password.</param>
        /// <param name="length">The lenght of the password.</param>
        /// <returns>The one-time generated password.</returns>
        public string GneratePassword(byte[] secredKey, DateTime time, int length)
        {
            var span = time.ToUniversalTime() - unixTime;
            var steps = (int) (span.TotalSeconds/TimeStep);

            return otpGenerator.GenerateOtp(steps, secredKey, length);
        }

        /// <summary>
        ///     Validates the <paramref name="providedPassword" /> based on the secred key, time, and length.
        /// </summary>
        /// <param name="providedPassword">The given password to validate.</param>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="length">The length of the password.</param>
        /// <param name="time">The time at which the password should be valid.</param>
        /// <returns>True if the provided password is valid, false otherwise.</returns>
        public bool ValidatePassword(string providedPassword, byte[] secretKey, int length, DateTime time)
        {
            var span = time.ToUniversalTime() - unixTime;
            var steps = (int) (span.TotalSeconds/TimeStep);
            var interval = (int) (Math.Abs(ValidityPeriod.TotalSeconds)/30);
            var minSteps = steps - interval;
            var maxSteps = steps + interval;

            for (var step = minSteps; step <= maxSteps; step++)
            {
                var generatedPassword = otpGenerator.GenerateOtp(step, secretKey, length);
                if (generatedPassword.Equals(providedPassword, StringComparison.InvariantCultureIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private readonly int DefaultPasswordLength = 6;
        private readonly IOtpGenerator otpGenerator;
        private readonly int TimeStep = 30;
        private readonly DateTime unixTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static readonly TimeSpan ValidityPeriod = TimeSpan.FromSeconds(60);
    }
}