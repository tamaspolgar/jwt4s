import sbt.Keys._

object Publish {
  val dontPublish = publishArtifact := false
}
