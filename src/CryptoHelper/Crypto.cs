using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace CrpytoHelper
{
    /// <summary>
    /// Provides helper methods for hashing/salting and verifying passwords.
    /// </summary>
    public static class Crypto
    {
        private const int PBKDF2IterCount = 10000; // use 10000 in stead of 1000.
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits

        /* =======================
         * HASHED PASSWORD FORMATS
         * =======================
         *
         * Version 0:
         * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
         * (See also: SDL crypto guidelines v5.1, Part III)
         * Format: { 0x00, salt, subkey }
         */

        /// <summary>
        /// Returns an RFC 2898 hash value for the specified password.
        /// </summary>
        /// <param name="password">The password to generate a hash value for.</param>
        /// <returns>The hash value for <paramref name="password" /> as a base-64-encoded string.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="password" /> is null.</exception>
        public static string HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            // Produce a version 0 (see comment above) password hash.
            byte[] salt;
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, SaltSize, PBKDF2IterCount))
            {
                salt = deriveBytes.Salt;
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }

            var outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(outputBytes);
        }

        /// <summary>
        /// Determines whether the specified RFC 2898 hash and password are a cryptographic match.
        /// </summary>
        /// <param name="hashedPassword">The previously-computed RFC 2898 hash value as a base-64-encoded string.</param>
        /// <param name="password">The plaintext password to cryptographically compare with hashedPassword.</param>
        /// <returns>true if the hash value is a cryptographic match for the password; otherwise, false.</returns>
        /// <remarks>
        /// <paramref name="hashedPassword" /> must be of the format of HashPassword (salt + Hash(salt+input).
        /// </remarks>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="hashedPassword" /> or <paramref name="password" /> is null.</exception>
        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException(nameof(hashedPassword));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            byte[] hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) password hash.
            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                // Wrong length or version header.
                return false;
            }

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);

            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }

        /// <summary>
        /// Generates a cryptographically strong sequence of random byte values.
        /// </summary>
        /// <param name="byteLength">The number of cryptographically random bytes to generate.</param>
        /// <returns>The generated salt value as a base-64-encoded string.</returns>
        public static string GenerateSalt(int byteLength = SaltSize)
        {
            return Convert.ToBase64String(GenerateSaltInternal(byteLength));
        }

        /// <summary>
        /// Returns a hash value for the specified string.
        /// </summary>
        /// <param name="input">The data to provide a hash value for.</param>
        /// <param name="algorithm">The algorithm that is used to generate the hash value. The default is "sha256".</param>
        /// <returns>The hash value for <paramref name="input" /> as a string of hexadecimal characters.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="input" /> is null.</exception>
        public static string Hash(string input, string algorithm = "sha256")
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            return Hash(Encoding.UTF8.GetBytes(input), algorithm);
        }

        /// <summary>
        /// Returns a hash value for the specified byte array.
        /// </summary>
        /// <param name="input">The data to provide a hash value for.</param>
        /// <param name="algorithm">The algorithm that is used to generate the hash value. The default is "sha256".</param>
        /// <returns>The hash value for input as a string of hexadecimal characters.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="input" /> is null.</exception>
        public static string Hash(byte[] input, string algorithm = "sha256")
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            using (var alg = CreateAlgorithm(algorithm))
            {
                byte[] hashData = alg.ComputeHash(input);
                return BinaryToHex(hashData);
            }
        }

        /// <summary>
        /// Returns a SHA-1 hash value for the specified string.
        /// </summary>
        /// <param name="input">The data to provide a hash value for.</param>
        /// <returns>The SHA-1 hash value for input as a string of hexadecimal characters.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="input" /> is null.</exception>
        public static string SHA1(string input)
        {
            return Hash(input, "sha1");
        }

        /// <summary>
        /// Returns a SHA-256 hash value for the specified string.
        /// </summary>
        /// <param name="input">The data to provide a hash value for.</param>
        /// <returns>The SHA-256 hash value for input as a string of hexadecimal characters.</returns>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="input" /> is null.</exception>
        public static string SHA256(string input)
        {
            return Hash(input);
        }

        private static HashAlgorithm CreateAlgorithm(string algorithm)
        {
            switch (algorithm.ToLower())
            {
                case "sha1":
                    return System.Security.Cryptography.SHA1.Create();

                case "sha256":
                    return System.Security.Cryptography.SHA256.Create();
            }

            throw new InvalidOperationException($"Unsupported hashing algorithm '{algorithm}'.");
        }

        private static byte[] GenerateSaltInternal(int byteLength = SaltSize)
        {
            var buf = new byte[byteLength];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buf);
            }
            return buf;
        }

        private static string BinaryToHex(byte[] data)
        {
            var hex = new char[data.Length * 2];

            for (var iter = 0; iter < data.Length; iter++)
            {
                var hexChar = ((byte)(data[iter] >> 4));
                hex[iter * 2] = (char)(hexChar > 9 ? hexChar + 0x37 : hexChar + 0x30);
                hexChar = ((byte)(data[iter] & 0xF));
                hex[(iter * 2) + 1] = (char)(hexChar > 9 ? hexChar + 0x37 : hexChar + 0x30);
            }
            return new string(hex);
        }

        // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
    }
}
