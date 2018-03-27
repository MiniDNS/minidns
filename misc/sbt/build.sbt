name := "MiniDNS Playground for Scala"

version := "1.0"

resolvers += Resolver.sonatypeRepo("snapshots")
resolvers += Resolver.mavenLocal

libraryDependencies += "org.minidns" % "minidns-client" % "latest.integration"
libraryDependencies += "org.minidns" % "minidns-dnssec" % "latest.integration"

initialCommands in console += "import org.minidns._;"
initialCommands in console += "import org.minidns.Record.TYPE;"
initialCommands in console += "val client = new DNSClient(new java.util.HashMap[Question,DNSMessage]())"

