# CryptoHelper
:key: Cryptography helper methods for hashing passwords using a PBKDF2 implementation.

<hr>

| Windows | Linux | OS X |
| --- | --- | --- |
| [![Build status](https://ci.appveyor.com/api/projects/status/hai0kndijmx6xb9d?svg=true)](https://ci.appveyor.com/project/henkmollema/cryptohelper) | [![Build Status](https://travis-ci.org/henkmollema/CryptoHelper.svg)](https://travis-ci.org/henkmollema/CryptoHelper) | [![Build Status](https://travis-ci.org/henkmollema/CryptoHelper.svg)](https://travis-ci.org/henkmollema/CryptoHelper) |

<hr>

This utility ports the password hashing functionality from the  [`System.Web.Helpers.Crypto`](http://aspnetwebstack.codeplex.com/SourceControl/latest#src/System.Web.Helpers/Crypto.cs) class to DNX. On DNX the new ASP.NET 5 Data Protection stack is used. Where as classic .NET 4.0 and 4.5 applications  will use `Rfc2898DeriveBytes` 

<hr>

#### [Download CryptoHelper on NuGet](https://www.nuget.org/packages/CryptoHelper)

--

#### Download using the NuGet Package Manager Console:
```
Install-Package CryptoHelper
```
