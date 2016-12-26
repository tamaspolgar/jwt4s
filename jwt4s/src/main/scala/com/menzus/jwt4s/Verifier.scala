package com.menzus.jwt4s

import java.time.Clock

import com.menzus.jwt4s.internal.Algorithm.verifySignature
import com.menzus.jwt4s.internal.Claims
import com.menzus.jwt4s.internal.Header.verifyAndExtractHeader
import com.menzus.jwt4s.internal.Payload.{verifyAndExtractClaims => verifyAndExtractIdClaimsPayload}
import com.menzus.jwt4s.internal.RawParts.verifyAndExtractRawParts
import com.menzus.jwt4s.internal.Result

trait Verifier {
  def verifyAndExtractClaims(jwtToken: String): Result[Claims]
}

object Verifier {

  def apply(settings: VerifierSettings)(implicit clock: Clock): Verifier = new Verifier {

    implicit val _settings = settings

    def verifyAndExtractClaims(jwtToken: String): Result[Claims] = for {
      rawParts <- verifyAndExtractRawParts(jwtToken)
      header   <- verifyAndExtractHeader(rawParts.headerBase64)
      claims   <- verifyAndExtractIdClaimsPayload(rawParts.payloadBase64)
      _        <- verifySignature(header, rawParts.headerBase64, rawParts.payloadBase64, rawParts.signatureBase64)
    } yield claims
  }
}