using Xunit;

namespace CryptoHelper.Tests
{
    public class CryptoHelperTests
    {
        private const string Password = "VerySecurePassword";

        [Fact]
        public void HashPassword_Returns_HashedPassword()
        {
            var hashed = Crypto.HashPassword(Password);
            Assert.NotEmpty(hashed);
        }

        [Fact]
        public void VeryifyHashedPasswordWithCorrectPassword_Returns_CorrectResult()
        {
            var hashed = Crypto.HashPassword(Password);
            var result = Crypto.VerifyHashedPassword(hashed, Password);
            Assert.True(result);
        }

        [Fact]
        public void VeryifyHashedPasswordWithIncorrectPassword_Returns_CorrectResult()
        {
            var hashed = Crypto.HashPassword(Password);
            var result = Crypto.VerifyHashedPassword(hashed, "WrongPassword");
            Assert.False(result);
        }
    }
}
