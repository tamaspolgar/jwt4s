import sbt.Keys._
import sbt._

private object Version {
  val Akka           = "2.4.11"
  val Cats           = "0.7.2"
  val Circe          = "0.5.3"
  val TypeSafeConfig = "1.3.1"

  val ScalaTest      = "3.0.0"
}

private object Library {
  val AkkaHttp        = "com.typesafe.akka" %% "akka-http-experimental" % Version.Akka
  val Cats            = "org.typelevel"     %% "cats"                   % Version.Cats
  val CirceCore       = "io.circe"          %% "circe-core"             % Version.Circe
  val CirceGeneric    = "io.circe"          %% "circe-generic"          % Version.Circe
  val CirceParser     = "io.circe"          %% "circe-parser"           % Version.Circe
  val TypeSafeConfig  = "com.typesafe"       % "config"                 % Version.TypeSafeConfig

  val AkkaHttpTestKit = "com.typesafe.akka" %% "akka-http-testkit"      % Version.Akka            % "test"
  val ScalaTest       = "org.scalatest"     %% "scalatest"              % Version.ScalaTest       % "test"
}

object Dependencies {

  import Library._

  val jwt4s = dependencies(
    CirceCore,
    CirceGeneric,
    CirceParser,
    TypeSafeConfig,

    ScalaTest
  )

  val jwt4sAkkaHttp = dependencies(
    AkkaHttp,
    CirceCore,
    CirceGeneric,
    CirceParser,
    TypeSafeConfig,

    AkkaHttpTestKit,
    ScalaTest
  )

  val jwt4sAkkaHttpExample = dependencies(
    CirceCore,
    CirceGeneric,
    CirceParser,
    TypeSafeConfig
  )

  private def dependencies(modules: ModuleID*): Seq[Setting[_]] = Seq(libraryDependencies ++= modules)
}