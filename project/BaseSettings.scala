import sbt.Keys._

object BaseSettings {
  lazy val defaultSettings = Seq(
    organization := "com.menzus",

    scalaVersion := "2.12.0",

    scalacOptions += "-feature",
    scalacOptions += "-deprecation",

    version := "0.0.2"
  )
}