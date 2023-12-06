plugins {
    kotlin("jvm") version "1.9.21"
    `maven-publish`
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
}

dependencies {
    implementation("org.projectlombok:lombok:1.18.22")
    implementation("org.apache.pdfbox:pdfbox:2.0.26")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    implementation(kotlin("stdlib-jdk8"))
    testImplementation("org.mockito:mockito-core:3.12.4")
    //html to pdf
    implementation("com.itextpdf:html2pdf:4.0.3")
}