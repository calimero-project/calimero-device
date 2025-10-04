plugins {
	`java-library`
	`maven-publish`
	signing
	id("com.github.ben-manes.versions") version "0.53.0"
	eclipse
}

repositories {
	mavenCentral()
	mavenLocal()
	maven("https://central.sonatype.com/repository/maven-snapshots/")
}

val junitJupiterVersion by rootProject.extra { "6.0.0" }

group = "io.calimero"
version = "3.0-SNAPSHOT"

java {
	toolchain {
		languageVersion.set(JavaLanguageVersion.of(21))
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

testing {
	suites {
		val test by getting(JvmTestSuite::class) {
			useJUnitJupiter("${rootProject.extra.get("junitJupiterVersion")}")

			targets {
				all {
					testTask.configure {
						options {
							val options = this as JUnitPlatformOptions
							options.excludeTags("knxnetip")
						}
					}
				}
			}
		}
	}
}

dependencies {
	api("io.calimero:calimero-core:$version")

	testRuntimeOnly("org.slf4j:slf4j-jdk-platform-logging:2.0.17")
	testRuntimeOnly("org.slf4j:slf4j-simple:2.0.17")
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
			val releasesRepoUrl = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
			val snapshotsRepoUrl = uri("https://central.sonatype.com/repository/maven-snapshots/")
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
