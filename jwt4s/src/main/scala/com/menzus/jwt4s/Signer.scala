package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Algorithm.createSignature
import com.menzus.jwt4s.internal.Header.asHeaderBase64
import com.menzus.jwt4s.internal.Header.createHeader
import com.menzus.jwt4s.internal.Result
import com.menzus.jwt4s.internal.Payload.createClaimsFor

trait Signer {
  def signTokenFor(subject: String): Result[String]
}

object Signer {

  def apply(settings: SignerSettings, clock: Clock) = new Signer {

    implicit val _settings = settings
    implicit val _clock = clock

    def signTokenFor(subject: String): Result[String] = for {
      header <- createHeader(settings.algorithm)
      headerBase64 <- asHeaderBase64(header)
      claimsBase64 <- createClaimsFor(subject)
      signatureBase64 <- createSignature(header, headerBase64, claimsBase64)
    } yield concat(headerBase64, claimsBase64, signatureBase64)


    private def concat(headerBase64: String, payloadBase64: String, signatureBase64: String) = {
      List(headerBase64, payloadBase64, signatureBase64).mkString(".")
    }
  }
}