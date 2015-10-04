name := "MiniDNS Playground for Scala"

version := "1.0"

resolvers += Resolver.sonatypeRepo("snapshots")
resolvers += Resolver.mavenLocal

libraryDependencies += "de.measite.minidns" % "minidns-core" % "latest.integration"
libraryDependencies += "de.measite.minidns" % "minidns-dnssec" % "latest.integration"

initialCommands in console += "import de.measite.minidns._;"
initialCommands in console += "import de.measite.minidns.Record.TYPE;"
initialCommands in console += "val client = new DNSClient(new java.util.HashMap[Question,DNSMessage]())"

