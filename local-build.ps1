param([switch]$SkipInstall)

$ErrorActionPreference = 'Stop'
$ghidraInstallDir = 'C:\bin\ghidra_12.1.2_PUBLIC'
$env:JAVA_HOME = (Resolve-Path "$PSScriptRoot\.gradle\jdks\jdk-21.0.12.1+1" -ErrorAction Stop).Path
$env:GRADLE_USER_HOME = "$PSScriptRoot\.gradle-user-home"
Push-Location $PSScriptRoot -ErrorAction Stop
try {
    # The optional HTML problems report can be unwritable in restricted builds.
    # Compiler diagnostics and build failures still appear in the console.
    .\gradlew.bat buildExtension "-PGHIDRA_INSTALL_DIR=$ghidraInstallDir" --no-problems-report @args
    $buildExitCode = $LASTEXITCODE
    if ($buildExitCode -eq 0 -and !$SkipInstall) {
        [xml]$pom = Get-Content -LiteralPath "$PSScriptRoot\pom.xml" -Raw
        $archive = Join-Path $PSScriptRoot "build\distributions\GhidraMCP-$($pom.project.version).zip"
        $userExtensionsDir = Join-Path $env:APPDATA "ghidra\$(Split-Path $ghidraInstallDir -Leaf)\Extensions"
        $extensionDir = Join-Path $userExtensionsDir 'GhidraMCP'
        $libDir = Join-Path $extensionDir 'lib'
        $backup = $null
        $oldJars = @(Get-ChildItem -LiteralPath $libDir -Filter 'GhidraMCP*.jar' -ErrorAction SilentlyContinue)

        # Check locks before changing any installed files. Windows holds the
        # loaded plugin JAR open until every Ghidra window has exited.
        foreach ($jar in $oldJars) {
            try {
                $handle = [System.IO.File]::Open($jar.FullName, 'Open', 'ReadWrite', 'None')
                $handle.Dispose()
            } catch {
                throw "Cannot install: $($jar.FullName) is locked or unwritable. Save your work, close Ghidra, then rerun local-build.ps1. Build succeeded; installed files were not changed. $($_.Exception.Message)"
            }
        }

        if (Test-Path -LiteralPath $extensionDir) {
            $backupDir = Join-Path $PSScriptRoot 'build\backups'
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            $backup = Join-Path $backupDir "GhidraMCP-before-install-$([guid]::NewGuid().ToString('N')).zip"
            Compress-Archive -LiteralPath $extensionDir -DestinationPath $backup
            Write-Host "Existing extension backed up to $backup"
        }

        # Validate extraction before removing stale versioned JARs, which
        # otherwise leave two definitions of the same plugin on the classpath.
        $stageDir = Join-Path $PSScriptRoot "build\install-stage-$([guid]::NewGuid().ToString('N'))"
        Expand-Archive -LiteralPath $archive -DestinationPath $stageDir
        $stagedExtension = Join-Path $stageDir 'GhidraMCP'
        if (!(Test-Path -LiteralPath "$stagedExtension\lib\GhidraMCP-$($pom.project.version).jar")) {
            throw "Extension archive is missing the expected plugin JAR: $archive"
        }
        New-Item -ItemType Directory -Path $libDir -Force | Out-Null
        try {
            foreach ($jar in $oldJars) {
                Remove-Item -LiteralPath $jar.FullName
            }
            Copy-Item -Path "$stagedExtension\*" -Destination $extensionDir -Recurse -Force
        } catch {
            $installFailure = $_
            if ($backup) {
                # Remove only plugin JARs introduced by this attempt, then
                # restore the complete previous extension from its backup.
                Get-ChildItem -LiteralPath $libDir -Filter 'GhidraMCP*.jar' |
                    Remove-Item -ErrorAction SilentlyContinue
                Expand-Archive -LiteralPath $backup -DestinationPath $userExtensionsDir -Force
            }
            throw $installFailure
        }
        Write-Host "Installed GhidraMCP $($pom.project.version) to $extensionDir. Start Ghidra to load it."
    }
} catch {
    Write-Error -Message $_ -ErrorAction Continue
    $buildExitCode = 1
} finally {
    Pop-Location
}
exit $buildExitCode
