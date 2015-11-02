using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

#if NET451 || DOTNET5_4
using Microsoft.AspNet.Cryptography.KeyDerivation;
#endif

namespace CryptoHelper
{
    /// <summary>
    /// Provides helper methods for hashing/salting and verifying passwords.
    /// </summary>
    public static class Crypto
    {
        /* =======================
         * HASHED PASSWORD FORMATS
         * =======================
         *
         * Version 0: (.NET 4 and 4.5)
         * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
         * (See also: SDL crypto guidelines v5.1, Part III)
         * Format: { 0x00, salt, subkey }
         *
         * Version 3: (DNX 4.5.1, 4.6 and Core 5.0)
         * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
         * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
         * (All UInt32s are stored big-endian.)
         */

#if NET40 || NET45
        private const int PBKDF2IterCount = 1000;
#else
        private const int PBKDF2IterCount = 10000;
#endif
        private const int PBKDF2SubkeyLength = 256 / 8; // 256 bits
        private const int SaltSize = 128 / 8; // 128 bits


        /// <summary>
        /// Returns a hashed representation of the specified <paramref name="password"/>.
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

            return HashPasswordInternal(password);
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
        /// <exception cref="T:System.ArgumentNullException">
        /// <paramref name="hashedPassword" /> or <paramref name="password" /> is
        /// null.
        /// </exception>
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

            return VerifyHashedPasswordInternal(hashedPassword, password);
        }

        // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
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

#if NET40 || NET45

        private static string HashPasswordInternal(string password)
        {
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

        private static bool VerifyHashedPasswordInternal(string hashedPassword, string password)
        {
            var decodedHashedPassword = Convert.FromBase64String(hashedPassword);

            // Verify a version 0 (see comment above) password hash.
            if (decodedHashedPassword.Length != (1 + SaltSize + PBKDF2SubkeyLength) || decodedHashedPassword[0] != 0x00)
            {
                // Wrong length or version header.
                return false;
            }

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(decodedHashedPassword, 1, salt, 0, SaltSize);

            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(decodedHashedPassword, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }
#endif

#if NET451 || DOTNET5_4
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        private static string HashPasswordInternal(string password)
        {
            var bytes = HashPasswordInternal(password, _rng, KeyDerivationPrf.HMACSHA256, PBKDF2IterCount, SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(bytes);
        }

        private static byte[] HashPasswordInternal(
            string password,
            RandomNumberGenerator rng,
            KeyDerivationPrf prf,
            int iterCount,
            int saltSize,
            int numBytesRequested)
        {
            // Produce a version 3 (see comment above) text hash.
            var salt = new byte[saltSize];
            rng.GetBytes(salt);
            var subkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, numBytesRequested);

            var outputBytes = new byte[13 + salt.Length + subkey.Length];
            outputBytes[0] = 0x01; // format marker
            WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
            WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
            WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);
            return outputBytes;
        }

        private static bool VerifyHashedPasswordInternal(string hashedPassword, string password)
        {
            var decodedHashedPassword = Convert.FromBase64String(hashedPassword);

            if (decodedHashedPassword.Length == 0)
            {
                return false;
            }

            try
            {
                // Read header information
                var prf = (KeyDerivationPrf)ReadNetworkByteOrder(decodedHashedPassword, 1);
                var iterCount = (int)ReadNetworkByteOrder(decodedHashedPassword, 5);
                var saltLength = (int)ReadNetworkByteOrder(decodedHashedPassword, 9);

                // Read the salt: must be >= 128 bits
                if (saltLength < 128 / 8)
                {
                    return false;
                }
                var salt = new byte[saltLength];
                Buffer.BlockCopy(decodedHashedPassword, 13, salt, 0, salt.Length);

                // Read the subkey (the rest of the payload): must be >= 128 bits
                var subkeyLength = decodedHashedPassword.Length - 13 - salt.Length;
                if (subkeyLength < 128 / 8)
                {
                    return false;
                }
                var expectedSubkey = new byte[subkeyLength];
                Buffer.BlockCopy(decodedHashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                // Hash the incoming password and verify it
                var actualSubkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, subkeyLength);
                return ByteArraysEqual(actualSubkey, expectedSubkey);
            }
            catch
            {
                // This should never occur except in the case of a malformed payload, where
                // we might go off the end of the array. Regardless, a malformed payload
                // implies verification failed.
                return false;
            }
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }

        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
        }
#endif
    }
}
