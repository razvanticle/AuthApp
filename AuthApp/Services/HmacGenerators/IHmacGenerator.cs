namespace AuthApp.Services.HmacGenerators
{
    public interface IHmacGenerator
    {
        byte[] ComputeHash(byte[] key, byte[] buffer);
    }
}