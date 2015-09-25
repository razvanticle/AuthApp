using System.Collections.Generic;
using System.Text;
using AuthApp.Services;
using AuthApp.Services.HmacGenerators;
using NUnit.Framework;

namespace AuthApp.Tests.Services
{
    [TestFixture]
    public class OtpGeneratorTests
    {
        [Test]
        [TestCaseSource("GetSha1TestCases")]
        public void GenerateOtp_WhenCalled_ReturnsTheCorrectOtp(int counter, string expectedResult)
        {
            // arrange
            var sha1HmacGenerator = new Sha1HmacGenerator();
            var sut = new OtpGenerator(sha1HmacGenerator);
            var secretKey = Encoding.ASCII.GetBytes("12345678901234567890");

            // act
            var actual = sut.GenerateOtp(counter, secretKey, 6);

            // assert
            Assert.AreEqual(actual, expectedResult);
        }

        private IEnumerable<TestCaseData> GetSha1TestCases()
        {
            yield return new TestCaseData(0, "755224");
            yield return new TestCaseData(1, "287082");
            yield return new TestCaseData(2, "359152");
            yield return new TestCaseData(3, "969429");
            yield return new TestCaseData(4, "338314");
            yield return new TestCaseData(5, "254676");
            yield return new TestCaseData(6, "287922");
            yield return new TestCaseData(7, "162583");
            yield return new TestCaseData(8, "399871");
            yield return new TestCaseData(9, "520489");
        }
    }
}