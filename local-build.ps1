$env:JAVA_HOME = (Resolve-Path '.gradle\jdks\jdk-21.0.12.1+1').Path
$env:GRADLE_USER_HOME = "$PWD\.gradle-user-home"
.\gradlew.bat buildExtension "-PGHIDRA_INSTALL_DIR=C:/bin/ghidra_12.1.2_PUBLIC"