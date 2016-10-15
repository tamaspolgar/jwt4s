lazy val root = Project("root", file("."))
  .settings(BaseSettings.defaultSettings: _*)
  .settings(Publish.dontPublish)
  .aggregate(`jwt`, `jwt4s-akka-http`)

lazy val `jwt` = Project("jwt4s", file("jwt4s"))
  .settings(BaseSettings.defaultSettings: _*)
  .settings(Dependencies.jwt4s: _*)

lazy val `jwt4s-akka-http` = Project("jwt4s-akka-http", file("jwt4s-akka-http"))
  .settings(BaseSettings.defaultSettings: _*)
  .settings(Dependencies.jwt4sAkkaHttp: _*)
  .dependsOn(`jwt`)