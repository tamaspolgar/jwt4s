import sbt.Keys._
import sbt._

private object Version {
  val Akka           = "10.0.4"
  val Cats           = "0.8.1"
  val Circe          = "0.7.0"
  val TypeSafeConfig = "1.3.1"

  val ScalaTest      = "3.0.1"
}

private object Library {
  val AkkaHttp        = "com.typesafe.akka" %% "akka-http"         % Version.Akka
  val Cats            = "org.typelevel"     %% "cats"              % Version.Cats
  val CirceCore       = "io.circe"          %% "circe-core"        % Version.Circe
  val CirceGeneric    = "io.circe"          %% "circe-generic"     % Version.Circe
  val CirceParser     = "io.circe"          %% "circe-parser"      % Version.Circe
  val TypeSafeConfig  = "com.typesafe"       % "config"            % Version.TypeSafeConfig

  val AkkaHttpTestKit = "com.typesafe.akka" %% "akka-http-testkit" % Version.Akka            % "test"
  val ScalaTest       = "org.scalatest"     %% "scalatest"         % Version.ScalaTest       % "test"
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