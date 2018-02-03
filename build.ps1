Write-Host "Executing build..."
dotnet build
if ($LASTEXITCODE -ne 0) {
    Write-Error  "Executing build failed"
    exit $LASTEXITCODE
}

Write-Host "Executing tests..."
dotnet test .\test\CryptoHelper.Tests\CryptoHelper.Tests.csproj
if ($LASTEXITCODE -ne 0) {
    Write-Error  "Executing tests failed"
    exit $LASTEXITCODE
}
