plugins {
	application
}

group = "io.calimero"
version = "3.0-SNAPSHOT"

application {
	mainClass.set("io.calimero.testnetwork.TestNetwork")
}

tasks.named<JavaExec>("run") {
	// for attaching to debugger, start with -Ddebug=true
	if (System.getProperty("debug", "false") == "true") {
		jvmArgs("-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=8000")
	}
	systemProperties(System.getProperties() as Map<String, *>)
	args("server-config.xml")
	standardInput = System.`in`
}

repositories {
	mavenCentral()
	mavenLocal()
	maven("https://central.sonatype.com/repository/maven-snapshots/")
}

dependencies {
	implementation("${group}:calimero-testnetwork:${version}")
}
