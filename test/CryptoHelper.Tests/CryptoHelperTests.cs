using Xunit;

namespace CryptoHelper.Tests
{
    public class CryptoHelperTests
    {
        private const string Password = "VerySecurePassword";
        private const string HashedPassword = "AQAAAAEAACcQAAAAEMZ9/7LS/Ne7087ytPjCosYJbysRf7DwrKzQziuhtA84k78soJGX0hQzNsNdnIrTNg==";

        [Fact]
        public void HashPassword_Returns_HashedPassword()
        {
            var hashed = Crypto.HashPassword(Password);
            Assert.NotEmpty(hashed);
        }

        [Fact]
        public void VerifyHashedPasswordWithCorrectPassword_Returns_CorrectResult()
        {
            var hashed = Crypto.HashPassword(Password);
            var result = Crypto.VerifyHashedPassword(hashed, Password);
            Assert.True(result);
        }

        [Fact]
        public void VerifyStoredPassword_Returns_CorrectResult()
        {
            // Test that verifies a previously hashed and stored password can
            // still be verified for backwards compatibility.
            var result = Crypto.VerifyHashedPassword(HashedPassword, Password);
            Assert.True(result);
        }

        [Fact]
        public void VerifyHashedPasswordWithIncorrectPassword_Returns_CorrectResult()
        {
            var hashed = Crypto.HashPassword(Password);
            var result = Crypto.VerifyHashedPassword(hashed, "WrongPassword");
            Assert.False(result);
        }
    }
}
