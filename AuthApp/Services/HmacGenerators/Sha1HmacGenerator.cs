using System.Security.Cryptography;

namespace AuthApp.Services.HmacGenerators
{
    public class Sha1HmacGenerator : IHmacGenerator
    {
        public byte[] ComputeHash(byte[] key, byte[] buffer)
        {
            var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(buffer);
        }
    }
}