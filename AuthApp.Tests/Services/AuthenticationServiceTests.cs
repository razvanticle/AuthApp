using System;
using System.Collections.Generic;
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
        [TestCaseSource("GetGeneratePasswordTestCases")]
        public void GeneratePassword_WhenHmacIsSha1_ReturnsExpectedResult(DateTime time, string expectedResult)
        {
            //arrange
            var secretKey = Encoding.ASCII.GetBytes("12345678901234567890");
            var sut = GetSut();

            //act
            var actual = sut.GneratePassword(secretKey, time, 8);

            //assert
            Assert.AreEqual(expectedResult, actual);
        }

        [Test]
        [TestCaseSource("GetValidatePasswordTestCases")]
        public void ValidatePassword_WhenCalled_ReturnsExpectedResult(DateTime time, bool expectedResult)
        {
            //arrange
            var secretKey = Encoding.ASCII.GetBytes("12345678901234567890");
            var sut = GetSut();

            //act
            var actual = sut.ValidatePassword("89005924", secretKey, 8, time);

            //assert
            Assert.AreEqual(expectedResult, actual);
        }
        
        private IAuthenticationService GetSut()
        {
            var hmacGenerator = new Sha1HmacGenerator();
            var otpGenerator = new OtpGenerator(hmacGenerator);
            var sut = new AuthenticationService(otpGenerator);

            return sut;
        }

        private IEnumerable<TestCaseData> GetValidatePasswordTestCases()
        {
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), true).SetName("Exact time returns true");

            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(-15), true).SetName("15 seconds prior returns true");
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(-60), true).SetName("60 seconds prior returns true");
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(-90), false).SetName("90 seconds prior returns false");

            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(15), true).SetName("15 seconds after returns true");
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(60), true).SetName("60 seconds after returns true");
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc).AddSeconds(90), false).SetName("90 seconds after returns false");
        }


        private IEnumerable<TestCaseData> GetGeneratePasswordTestCases()
        {
            yield return new TestCaseData(new DateTime(1970, 1, 1, 0, 0, 59, DateTimeKind.Utc), "94287082");
            yield return new TestCaseData(new DateTime(2005, 3, 18, 1, 58, 29, DateTimeKind.Utc), "07081804");
            yield return new TestCaseData(new DateTime(2005, 3, 18, 1, 58, 31, DateTimeKind.Utc), "14050471");
            yield return new TestCaseData(new DateTime(2009, 2, 13, 23, 31, 30, DateTimeKind.Utc), "89005924");
            yield return new TestCaseData(new DateTime(2033, 5, 18, 3, 33, 20, DateTimeKind.Utc), "69279037");
            yield return new TestCaseData(new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc), "65353130");
        }
    }
}