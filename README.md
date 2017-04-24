# CryptoHelper
:key: Standalone password hasher for ASP.NET Core using a PBKDF2 implementation.

<hr>

| Windows | Linux | OS X |
| --- | --- | --- |
| [![Build status](https://ci.appveyor.com/api/projects/status/hai0kndijmx6xb9d?svg=true)](https://ci.appveyor.com/project/henkmollema/cryptohelper) | [![Build Status](https://travis-ci.org/henkmollema/CryptoHelper.svg)](https://travis-ci.org/henkmollema/CryptoHelper) | [![Build Status](https://travis-ci.org/henkmollema/CryptoHelper.svg)](https://travis-ci.org/henkmollema/CryptoHelper) |

<hr>

This utility provides a standalone password hasher for ASP.NET Core without a dependency on ASP.NET Identity. The passwords are hashed using the new [Data Protection](https://github.com/aspnet/DataProtection) stack.

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
    return Crypto.HashPassword(password);
}

// Verify the password hash against the given password
public bool VerifyPassword(string hash, string password)
{
    return Crypto.VerifyHashedPassword(hash, password);
}
```
