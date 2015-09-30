using System;
using System.Text;
using AuthApp.Services;
using AuthApp.Services.HmacGenerators;

namespace AuthApp
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var userId = "123456";
            var currentDate = DateTime.Now;

            var hmacGenerator = new Sha1HmacGenerator();
            var otpGenerator = new OtpGenerator(hmacGenerator);
            var authenticationService = new AuthenticationService(otpGenerator);

            var password = authenticationService.GneratePassword(Encoding.ASCII.GetBytes(userId), currentDate);

            Console.WriteLine("Yor password is: {0}", password);
            Console.ReadKey();
        }
    }
}