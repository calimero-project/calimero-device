plugins {
	`java-library`
	`maven-publish`
	signing
	id("com.github.ben-manes.versions") version "0.51.0"
	eclipse
}

repositories {
	mavenLocal()
	mavenCentral()
	maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
}

val junitJupiterVersion = "5.11.3"

group = "io.calimero"
version = "3.0-SNAPSHOT"

java {
	toolchain {
		languageVersion.set(JavaLanguageVersion.of(17))
	}
	withSourcesJar()
	withJavadocJar()
}

tasks.withType<Jar>().configureEach {
	from(projectDir) {
		include("LICENSE")
		into("META-INF")
	}
	if (name == "sourcesJar") {
		from(projectDir) {
			include("README.md")
		}
	}
}

tasks.withType<JavaCompile>().configureEach {
	options.encoding = "UTF-8"
}

tasks.withType<Javadoc>().configureEach {
	options.encoding = "UTF-8"
	(options as CoreJavadocOptions).addStringOption("Xdoclint:-missing", "-quiet")
}

tasks.withType<JavaCompile>().configureEach {
	options.compilerArgs.addAll(listOf("-Xlint:all,-serial"))
}

tasks.withType<JavaCompile>().configureEach {
	options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-try"))
}

tasks.named<JavaCompile>("compileJava") {
	options.javaModuleVersion = project.version.toString()
}

tasks.named<Test>("test") {
	useJUnitPlatform {
		excludeTags("knxnetip")
	}
}

dependencies {
	api("io.calimero:calimero-core:$version")

	testImplementation("org.junit.jupiter:junit-jupiter:$junitJupiterVersion")
	testRuntimeOnly("org.slf4j:slf4j-jdk-platform-logging:2.0.16")
	testRuntimeOnly("org.slf4j:slf4j-simple:2.0.16")
}

publishing {
	publications {
		create<MavenPublication>("mavenJava") {
			artifactId = rootProject.name
			from(components["java"])
			pom {
				name.set("Calimero KNX Device")
				description.set("Communication stack for a Calimero KNX Device")
				url.set("https://github.com/calimero-project/calimero-device")
				inceptionYear.set("2006")
				licenses {
					license {
						name.set("GNU General Public License, version 2, with the Classpath Exception")
						url.set("LICENSE")
					}
				}
				developers {
					developer {
						name.set("Boris Malinowsky")
						email.set("b.malinowsky@gmail.com")
					}
				}
				scm {
					connection.set("scm:git:git://github.com/calimero-project/calimero-device.git")
					url.set("https://github.com/calimero-project/calimero-device.git")
				}
			}
		}
	}
	repositories {
		maven {
			name = "maven"
			val releasesRepoUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2")
			val snapshotsRepoUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots")
			url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
			credentials(PasswordCredentials::class)
		}
	}
}

signing {
	if (project.hasProperty("signing.keyId")) {
		sign(publishing.publications["mavenJava"])
	}
}
