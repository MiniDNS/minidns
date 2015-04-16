name := "MiniDNS Playground for Scala"

version := "1.0"

resolvers += Resolver.sonatypeRepo("snapshots")
resolvers += Resolver.mavenLocal

libraryDependencies += "de.measite.minidns" % "minidns" % "latest.integration"

initialCommands in console += "import de.measite.minidns._;"
initialCommands in console += "import de.measite.minidns.Record.TYPE;"
initialCommands in console += "val client = new Client()"

