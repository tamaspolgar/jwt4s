import sbt.Keys._

object BaseSettings {
  lazy val defaultSettings = Seq(
    organization := "com.menzus",

    scalaVersion := "2.11.8",

    version := "0.0.2-SNAPSHOT"
  )
}