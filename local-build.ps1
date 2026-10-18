$env:JAVA_HOME = (Resolve-Path "$PSScriptRoot\.gradle\jdks\jdk-21.0.12.1+1" -ErrorAction Stop).Path
$env:GRADLE_USER_HOME = "$PSScriptRoot\.gradle-user-home"
Push-Location $PSScriptRoot -ErrorAction Stop
try {
    # The optional HTML problems report can be unwritable in restricted builds.
    # Compiler diagnostics and build failures still appear in the console.
    .\gradlew.bat buildExtension "-PGHIDRA_INSTALL_DIR=C:/bin/ghidra_12.1.2_PUBLIC" --no-problems-report @args
    $buildExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $buildExitCode
