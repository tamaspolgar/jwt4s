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
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig, "hmac-secret-key-base64"),
      algorithm = Settings.asAlgorithm(jwtConfig, "signer.algorithm"),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      expiresInS = jwtConfig.getDuration("signer.expires-in").getSeconds
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
  val maxLifeTimeInS: Long
)

object VerifierSettings {

  def apply(config: Config): VerifierSettings = {
    val jwtConfig = Settings.jwtConfig(config)

    VerifierSettings(
      hmacSecretKey = Settings.hmacSecretKey(jwtConfig, "hmac-secret-key-base64"),
      audience = jwtConfig.getString("audience"),
      issuer = jwtConfig.getString("issuer"),
      acceptedAlgHeaders = Settings.asAlgHeaders(jwtConfig, "verifier.accepted-alg-headers"),
      expToleranceInS = jwtConfig.getDuration("verifier.exp.tolerance").getSeconds,
      iatToleranceInS = jwtConfig.getDuration("verifier.iat.tolerance").getSeconds,
      maxLifeTimeInS = jwtConfig.getDuration("verifier.max-life-time").getSeconds
    )
  }
}

object Settings {
  private val referenceConfig = ConfigFactory.load("reference.conf")

  def jwtConfig(config: Config) = config.withFallback(referenceConfig).getConfig("jwt")

  def hmacSecretKey(jwtConfig: Config, path: String) = {
    extractBytesFromBase64(jwtConfig.getString(path))
      .getOrElse(throw new BadValue(path, "not a valid base64 encoded string"))
  }

  def asAlgorithm(alg: String, path: String): Algorithm = {
    algHeaderToAlgorithm(alg)
      .getOrElse(throw new BadValue(path, s"unknown algorithm $alg"))
  }

  def asAlgorithm(jwtConfig: Config, path: String): Algorithm = {
    asAlgorithm(jwtConfig.getString(path), path)
  }

  def asAlgHeaders(jwtConfig: Config, path: String) = {
    asScalaBuffer(jwtConfig.getStringList(path)).toSet[String]
      .map(alg => Settings.asAlgorithm(alg, path))
  }
}