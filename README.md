# CryptoHelper
🔑 Standalone password hasher for ASP.NET Core using a PBKDF2 implementation.

<hr>

This utility provides a standalone password hasher for ASP.NET Core without a dependency on ASP.NET Identity. The passwords are hashed using the Data Protection stack of ASP.NET Core.

<hr>

## Download

CryptoHelper is available on [NuGet](https://www.nuget.org/packages/CryptoHelper).

<hr>

## Usage
```csharp
using CryptoHelper;

// Hash a password
public string HashPassword(string password)
{
    return PasswordHasher.HashPassword(password);
}

// Verify the password hash against the given password
public bool VerifyPassword(string hash, string password)
{
    return PasswordHasher.VerifyHashedPassword(hash, password);
}
```

> [!WARNING]
> The class name `Crypto` has been changed to `PasswordHasher`.