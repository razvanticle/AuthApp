namespace AuthApp.Services
{
    public interface IOtpGenerator
    {
        /// <summary>
        ///  Generates the one-time password for the given <paramref name="counter"/> value.
        /// </summary>
        /// <param name="counter">The counter value to use.</param>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="length">The number of digits in the OTP to generate.</param>
        /// <returns>The one-time password for the given input.</returns>
        string GenerateOtp(int counter, byte[] secretKey, int length);
    }
}