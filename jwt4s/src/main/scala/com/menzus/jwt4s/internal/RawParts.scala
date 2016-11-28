package com.menzus.jwt4s.internal

import com.menzus.jwt4s.error.InvalidStructure

case class RawParts(headerBase64: String, payloadBase64: String, signatureBase64: String)

object RawParts {

  private val JwtRegExp = "([a-zA-Z0-9-_]+)\\.([a-zA-Z0-9-_]+)\\.([a-zA-Z0-9-_]+)".r

  def verifyAndExtractRawParts(jwt: String): Result[RawParts] = {
    jwt match {
      case JwtRegExp(headerBase64, payloadBase64, signatureBase64) =>
        Right(RawParts(headerBase64, payloadBase64, signatureBase64))
      case _ =>
        Left(InvalidStructure)
    }
  }
}