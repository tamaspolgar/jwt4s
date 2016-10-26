package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Algorithm.verifySignature
import com.menzus.jwt4s.internal.Claims
import com.menzus.jwt4s.internal.Header.verifyAndExtractHeader
import com.menzus.jwt4s.internal.Result
import com.menzus.jwt4s.internal.Payload.verifyAndExtractClaims
import com.menzus.jwt4s.internal.RawParts.verifyAndExtractRawParts

trait Verifier[A] {
  def verifyAndExtract(jwtToken: String): Result[A]
}

object Verifier {

  def apply(settings: VerifierSettings, clock: Clock): Verifier[Claims] = new Verifier[Claims] {

    implicit val _settings = settings
    implicit val _clock = clock

    def verifyAndExtract(jwtToken: String): Result[Claims] = for {
      rawParts <- verifyAndExtractRawParts(jwtToken)
      header   <- verifyAndExtractHeader(rawParts.headerBase64)
      claims   <- verifyAndExtractClaims(rawParts.payloadBase64)
      _        <- verifySignature(header, rawParts.headerBase64, rawParts.payloadBase64, rawParts.signatureBase64)
    } yield claims
  }

  //todo this should be composable like functions
  def subjectVerifier(settings: VerifierSettings, clock: Clock): Verifier[String] = new Verifier[String] {

    implicit val _settings = settings
    implicit val _clock = clock

    def verifyAndExtract(jwtToken: String): Result[String] = for {
      rawParts <- verifyAndExtractRawParts(jwtToken)
      header   <- verifyAndExtractHeader(rawParts.headerBase64)
      claims   <- verifyAndExtractClaims(rawParts.payloadBase64)
      _        <- verifySignature(header, rawParts.headerBase64, rawParts.payloadBase64, rawParts.signatureBase64)
    } yield claims.sub
  }
}