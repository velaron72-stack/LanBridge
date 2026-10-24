import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm") version "2.0.21"
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21"
    id("org.jetbrains.compose") version "1.7.3"
}

// Version of the app: the same numbers as the Android module, so the phone and the PC always show the same build.
val androidBuild = rootProject.projectDir.resolve("../app/build.gradle.kts").readText()
val appVersionName: String = Regex("""versionName\s*=\s*"([^"]+)"""").find(androidBuild)?.groupValues?.get(1)
    ?: error("versionName not found in app/build.gradle.kts")
val appVersionCode: String = Regex("""versionCode\s*=\s*(\d+)""").find(androidBuild)?.groupValues?.get(1)
    ?: error("versionCode not found in app/build.gradle.kts")

group = "app.lanbridge"
version = appVersionName


dependencies {
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation("org.jetbrains.compose.material:material-icons-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.9.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("org.json:json:20240303")
}

// The protocol core, the engine controller and the shared screens are the Android sources, compiled here unchanged.
// Only the files listed below are taken: everything that touches Android (service, activity, camera, system dialogs)
// has its own version under src/main/kotlin. The android.* classes the shared files import are small shims there.
val sharedRoot = rootProject.projectDir.resolve("../app/src/main/java/app/lanbridge")
val sharedFiles = listOf(
    "core/HintMailbox.kt",
    "core/LanSelfTest.kt",
    "core/Native.kt",
    "core/OfferCodec.kt",
    "core/Prefs.kt",
    "core/TunnelController.kt",
    "ui/Fmt.kt",
    "ui/GroupScreens.kt",
    "ui/Theme.kt",
)

val syncShared = tasks.register<Sync>("syncSharedSources") {
    from(sharedRoot) { include(sharedFiles) }
    into(layout.buildDirectory.dir("shared-src/app/lanbridge"))
    doFirst {
        val missing = sharedFiles.filter { !sharedRoot.resolve(it).isFile }
        if (missing.isNotEmpty()) throw GradleException("shared sources not found: $missing")
    }
}

kotlin.sourceSets.named("main") {
    kotlin.srcDir(layout.buildDirectory.dir("shared-src"))
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(syncShared)
}

tasks.processResources {
    inputs.property("versionName", appVersionName)
    inputs.property("versionCode", appVersionCode)
    filesMatching("version.properties") {
        expand("versionName" to appVersionName, "versionCode" to appVersionCode)
    }
}

// Windows: the packaged app expects lanbridge.dll and wintun.dll in resources/windows-x64 (CI puts them there).
tasks.register("checkNativeFiles") {
    group = "verification"
    description = "Fails when lanbridge.dll or wintun.dll is missing from desktop/resources/windows-x64."
    doLast {
        val dir = projectDir.resolve("resources/windows-x64")
        val missing = listOf("lanbridge.dll", "wintun.dll").filter { !dir.resolve(it).isFile }
        if (missing.isNotEmpty()) throw GradleException("missing in ${dir.path}: $missing")
    }
}

// An installer or app image without the two libraries would start and then fail: refuse to build one.
tasks.matching { it.name in setOf("createDistributable", "packageExe", "packageMsi") }.configureEach {
    dependsOn("checkNativeFiles")
}

compose.desktop {
    application {
        mainClass = "app.lanbridge.MainKt"
        jvmArgs += listOf("-Dfile.encoding=UTF-8", "-Dsun.stdout.encoding=UTF-8", "-Xmx256m", "-XX:+UseSerialGC")

        nativeDistributions {
            targetFormats(TargetFormat.Exe, TargetFormat.Msi)
            packageName = "LanBridge"
            packageVersion = appVersionName
            description = "LanBridge: virtual LAN over P2P, no servers"
            vendor = "LanBridge"
            copyright = "LanBridge"
            appResourcesRootDir.set(layout.projectDirectory.dir("resources"))
            modules("java.naming", "jdk.unsupported")

            windows {
                iconFile.set(layout.projectDirectory.file("icons/lanbridge.ico"))
                menu = true
                menuGroup = "LanBridge"
                shortcut = true
                dirChooser = true
                perUserInstall = false
                console = false
                upgradeUuid = "5C0E2A47-8B1D-4C63-A9F4-3D7E21B6C0A8"
            }
        }
    }
}
