using System;
using AuthApp.Services.HmacGenerators;

namespace AuthApp.Services
{
    /// <summary>
    ///     Generates one-time passwords based on the HOTP algorithm. https://www.ietf.org/rfc/rfc4226.txt
    /// </summary>
    public class OtpGenerator : IOtpGenerator
    {
        /// <summary>
        ///     Initializes a new instance of OtpGenerator class.
        /// </summary>
        /// <param name="hmacGenerator">The HMAC generator used for generating the password hash.</param>
        public OtpGenerator(IHmacGenerator hmacGenerator)
        {
            this.hmacGenerator = hmacGenerator;
        }

        /// <summary>
        ///     Generates the one-time password for the given <paramref name="counter" /> value.
        /// </summary>
        /// <param name="counter">The counter value to use.</param>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="length">The number of digits in the OTP to generate.</param>
        /// <returns>The one-time password for the given input.</returns>
        public virtual string GenerateOtp(int counter, byte[] secretKey, int length)
        {
            var counterBytes = BitConverter.GetBytes(counter);
            Array.Resize(ref counterBytes, 8);
            Array.Reverse(counterBytes);

            var hash = hmacGenerator.ComputeHash(secretKey, counterBytes);
            var offset = hash[hash.Length - 1] & 0xF;

            var binary = ((hash[offset] & 0x7F) << 24) |
                         ((hash[offset + 1] & 0xFF) << 16) |
                         ((hash[offset + 2] & 0xFF) << 8) |
                         (hash[offset + 3] & 0xFF);

            var otp = binary%DigitsPower[length];
            var result = otp.ToString("D" + length);

            return result;
        }

        private readonly IHmacGenerator hmacGenerator;

        private static readonly int[] DigitsPower =
        {
            1,
            10,
            100,
            1000,
            10000,
            100000,
            1000000,
            10000000,
            100000000
        };
    }
}