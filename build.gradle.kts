plugins {
    kotlin("jvm") version "2.0.21"
    application
}

group = "netscope"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("net.java.dev.jna:jna:5.14.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

application {
    mainClass.set("netscope.MainKt")
    applicationName = "netscope"
    applicationDefaultJvmArgs = listOf(
        "-Dfile.encoding=UTF-8",
        "-Dsun.stdout.encoding=UTF-8",
        "-Dsun.stderr.encoding=UTF-8",
        "-Dstdout.encoding=UTF-8"
    )
}

tasks.withType<JavaExec>().configureEach {
    standardInput = System.`in`
    if (System.getProperty("os.name").lowercase().contains("win")) {
        jvmArgs("-Dfile.encoding=UTF-8", "-Dsun.stdout.encoding=UTF-8", "-Dsun.stderr.encoding=UTF-8", "-Dstdout.encoding=UTF-8")
    }
}
