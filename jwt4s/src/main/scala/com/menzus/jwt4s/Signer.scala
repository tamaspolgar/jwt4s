package com.menzus.jwt4s

import java.time.Clock

import com.menzus.jwt4s.internal.Algorithm.createSignature
import com.menzus.jwt4s.internal.Header.asHeaderBase64
import com.menzus.jwt4s.internal.Header.createHeader
import com.menzus.jwt4s.internal.Payload.createIdClaimsFor
import com.menzus.jwt4s.internal.Payload.createRfpClaimsFor

case class Token(idToken: String, expiresIn: Long)

trait Signer {
  def signSubject(sub: String): Token
  def signSubjectAndRoles(sub: String, roles: Set[String]): Token
  def signRequestForgeryProtection(rfp: String): Token
}

object Signer {

  def apply(settings: SignerSettings)(implicit clock: Clock) = new Signer {

    implicit val _settings = settings

    def signSubject(sub: String): Token =  signSubjectAndRoles(sub, Set())

    def signSubjectAndRoles(sub: String, roles: Set[String]): Token = {
      val header          = createHeader(settings.algorithm)
      val headerBase64    = asHeaderBase64(header)
      val claimsBase64    = createIdClaimsFor(sub, roles)
      val signatureBase64 = createSignature(header, headerBase64, claimsBase64)

      Token(
        idToken = concat(headerBase64, claimsBase64, signatureBase64),
        expiresIn = settings.expiresInS
      )
    }

    def signRequestForgeryProtection(rfp: String): Token = {
      val header          = createHeader(settings.algorithm)
      val headerBase64    = asHeaderBase64(header)
      val claimsBase64    = createRfpClaimsFor(rfp)
      val signatureBase64 = createSignature(header, headerBase64, claimsBase64)

      Token(
        idToken = concat(headerBase64, claimsBase64, signatureBase64),
        expiresIn = settings.expiresInS
      )
    }

    private def concat(headerBase64: String, payloadBase64: String, signatureBase64: String) = {
      List(headerBase64, payloadBase64, signatureBase64).mkString(".")
    }
  }
}