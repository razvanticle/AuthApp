using System.Security.Cryptography;

namespace AuthApp.Services.HmacGenerators
{
    public class Sha256HmacGenerator : IHmacGenerator
    {
        public byte[] ComputeHash(byte[] key, byte[] buffer)
        {
            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(buffer);
        }
    }
}