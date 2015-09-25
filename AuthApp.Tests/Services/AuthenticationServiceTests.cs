using System;
using System.Text;
using AuthApp.Services;
using AuthApp.Services.HmacGenerators;
using NUnit.Framework;

namespace AuthApp.Tests.Services
{
    [TestFixture]
    public class AuthenticationServiceTests
    {
        [Test]
        public void Test()
        {
            var hmacGenerator = new Sha256HmacGenerator();
            var otpGenerator = new OtpGenerator(hmacGenerator);

            var secretKey = Encoding.ASCII.GetBytes("12345678901234567890");
            

            var time = new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc);

            var sut = new AuthenticationService(otpGenerator);

            var actual = sut.GneratePassword(secretKey, time, 8);

            Assert.AreEqual(actual, "46119246");
        }
    }
}