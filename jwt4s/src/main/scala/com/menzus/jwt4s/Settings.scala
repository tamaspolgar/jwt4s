package com.menzus.jwt4s

import com.menzus.jwt4s.internal.extractBytesFromBase64
import com.typesafe.config.Config
import com.typesafe.config.ConfigException.BadValue
import com.typesafe.config.ConfigFactory

import scala.collection.JavaConversions._

case class SignerSettings(
  hmacSecretKey: Array[Byte],
  algorithm: String,
  audience: String,
  issuer: String,
  maxAgeInS: Long
)

object SignerSettings {

  def apply(): SignerSettings = {
    apply(ConfigFactory.load)
  }

  def apply(config: Config): SignerSettings = {
    val jwtConfig = Settings.jwtConfig(config)

    SignerSettings(
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig),
      algorithm = jwtConfig.getString("algorithm"),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      maxAgeInS = jwtConfig.getLong("nbf.tolerance-in-seconds")
    )
  }
}

case class VerifierSettings (
  val hmacSecretKey: Array[Byte],
  val audience: String,
  val issuer: String,
  val acceptedAlgHeaders: Set[String],
  val expToleranceInS: Long,
  val iatToleranceInS: Long,
  val nbfToleranceInS: Long
)

object VerifierSettings {

  def apply(): VerifierSettings = {
    apply(ConfigFactory.load)
  }

  def apply(config: Config): VerifierSettings = {
    val jwtConfig = Settings.jwtConfig(config)

    VerifierSettings(
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      acceptedAlgHeaders = jwtConfig.getStringList("accepted-alg-headers").toSet,
      expToleranceInS = jwtConfig.getLong("exp.tolerance-in-seconds"),
      iatToleranceInS = jwtConfig.getLong("iat.tolerance-in-seconds"),
      nbfToleranceInS = jwtConfig.getLong("nbf.tolerance-in-seconds")
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
}