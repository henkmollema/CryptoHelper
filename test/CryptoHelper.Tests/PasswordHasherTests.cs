using System;
using Xunit;

namespace CryptoHelper.Tests;

public class PasswordHasherTests
{
    private const string Password = "VerySecurePassword";
    private const string HashedPassword = "AQAAAAEAACcQAAAAEMZ9/7LS/Ne7087ytPjCosYJbysRf7DwrKzQziuhtA84k78soJGX0hQzNsNdnIrTNg==";

    [Fact]
    public void HashPassword_Returns_HashedPassword()
    {
        var hashed = PasswordHasher.HashPassword(Password);
        Assert.NotEmpty(hashed);
    }

    [Fact]
    public void VerifyHashedPasswordWithCorrectPassword_Returns_CorrectResult()
    {
        var hashed = PasswordHasher.HashPassword(Password);
        var result = PasswordHasher.VerifyHashedPassword(hashed, Password);
        Assert.True(result);
    }

    [Fact]
    public void HashPassword_Obsolete()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        var hashed = Crypto.HashPassword(Password);
        var result = PasswordHasher.VerifyHashedPassword(hashed, Password);
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.True(result);
    }

    [Fact]
    public void VerifyHashedPassword_Obsolete()
    {
#pragma warning disable CS0618 // Type or member is obsolete
        var hashed = PasswordHasher.HashPassword(Password);
        var result = Crypto.VerifyHashedPassword(hashed, Password);
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.True(result);
    }

    [Fact]
    public void VerifyStoredPassword_Returns_CorrectResult()
    {
        // Test that verifies a previously hashed and stored password can
        // still be verified for backwards compatibility.
        var result = PasswordHasher.VerifyHashedPassword(HashedPassword, Password);
        Assert.True(result);
    }

    [Fact]
    public void VerifyHashedPasswordWithIncorrectPassword_Returns_CorrectResult()
    {
        var hashed = PasswordHasher.HashPassword(Password);
        var result = PasswordHasher.VerifyHashedPassword(hashed, "WrongPassword");
        Assert.False(result);
    }

    [Fact]
    public void HashPassword_EmptyPassword_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => PasswordHasher.HashPassword(""));
    }

    [Fact]
    public void VerifyHashedPassword_WeakPrf_ReturnsFalse()
    {
        // Craft a hash with HMACSHA1 (prf = 0) — should be rejected.
        var hash = CreateTamperedHash(prf: 0);
        Assert.False(PasswordHasher.VerifyHashedPassword(hash, Password));
    }

    [Fact]
    public void VerifyHashedPassword_LowIterationCount_ReturnsFalse()
    {
        // Craft a hash with only 1 iteration — should be rejected.
        var hash = CreateTamperedHash(iterCount: 1);
        Assert.False(PasswordHasher.VerifyHashedPassword(hash, Password));
    }

    [Fact]
    public void VerifyHashedPassword_HugeSaltLength_ReturnsFalse()
    {
        // Craft a hash with an absurdly large salt length.
        var hash = CreateTamperedHash(saltLength: 1_000_000);
        Assert.False(PasswordHasher.VerifyHashedPassword(hash, Password));
    }

    [Fact]
    public void VerifyHashedPassword_MalformedPayload_ReturnsFalse()
    {
        Assert.False(PasswordHasher.VerifyHashedPassword(Convert.ToBase64String(new byte[] { 0x01 }), Password));
    }

    /// <summary>
    /// Creates a base64 hash payload with tampered header fields for testing validation.
    /// </summary>
    private static string CreateTamperedHash(uint prf = 1, uint iterCount = 600_000, uint saltLength = 16)
    {
        var salt = new byte[16];
        var subkey = new byte[32];
        var output = new byte[13 + salt.Length + subkey.Length];
        output[0] = 0x01;
        WriteBE(output, 1, prf);
        WriteBE(output, 5, iterCount);
        WriteBE(output, 9, saltLength);
        Buffer.BlockCopy(salt, 0, output, 13, salt.Length);
        Buffer.BlockCopy(subkey, 0, output, 13 + salt.Length, subkey.Length);
        return Convert.ToBase64String(output);
    }

    private static void WriteBE(byte[] buf, int offset, uint value)
    {
        buf[offset + 0] = (byte)(value >> 24);
        buf[offset + 1] = (byte)(value >> 16);
        buf[offset + 2] = (byte)(value >> 8);
        buf[offset + 3] = (byte)(value >> 0);
    }
}
