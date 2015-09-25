using System.Security.Cryptography;

namespace AuthApp.Services.HmacGenerators
{
    public class Sha512HmacGenerator : IHmacGenerator
    {
        public byte[] ComputeHash(byte[] key, byte[] buffer)
        {
            var hmac = new HMACSHA512(key);
            return hmac.ComputeHash(buffer);
        }
    }
}