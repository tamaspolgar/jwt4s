package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Algorithm
import com.menzus.jwt4s.internal.Algorithm.algHeaderToAlgorithm
import com.menzus.jwt4s.internal.extractBytesFromBase64
import com.typesafe.config.Config
import com.typesafe.config.ConfigException.BadValue
import com.typesafe.config.ConfigFactory

import scala.collection.JavaConverters.asScalaBuffer

case class SignerSettings(
  hmacSecretKey: Array[Byte],
  algorithm: Algorithm,
  audience: String,
  issuer: String,
  expiresInS: Long
)

object SignerSettings {

  def apply(config: Config): SignerSettings = {
    val jwtConfig = Settings.jwtConfig(config)

    SignerSettings(
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig),
      algorithm = Settings.asAlgorithm(jwtConfig.getString("algorithm"), "algorithm"),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      expiresInS = jwtConfig.getDuration("expires-in").getSeconds
    )
  }
}

case class VerifierSettings (
  val hmacSecretKey: Array[Byte],
  val audience: String,
  val issuer: String,
  val acceptedAlgHeaders: Set[Algorithm],
  val expToleranceInS: Long,
  val iatToleranceInS: Long,
  val maxLifeTime: Long
)

object VerifierSettings {

  def apply(config: Config): VerifierSettings = {
    val jwtConfig = Settings.jwtConfig(config)

    VerifierSettings(
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      acceptedAlgHeaders = asScalaBuffer(jwtConfig.getStringList("accepted-alg-headers")).toSet[String]
        .map(alg => Settings.asAlgorithm(alg, "accepted-alg-headers")),
      expToleranceInS = jwtConfig.getDuration("exp.tolerance").getSeconds,
      iatToleranceInS = jwtConfig.getDuration("iat.tolerance").getSeconds,
      maxLifeTime = jwtConfig.getDuration("max-life-time").getSeconds
    )
  }
}

object Settings {
  private val referenceConfig = ConfigFactory.load("reference.conf")

  def jwtConfig(config: Config) = config.withFallback(referenceConfig).getConfig("jwt")

  def hmacSecretKey(jwtConfig: Config) = {
    extractBytesFromBase64(jwtConfig.getString("hmac-secret-key-base64"))
      .getOrElse(throw new BadValue("hmac-secret-key-base64", "not a valid base64 encoded string"))
  }

  def asAlgorithm(alg: String, path: String) = {
    algHeaderToAlgorithm(alg).getOrElse(throw new BadValue(path, s"unknown algorithm $alg"))
  }
}