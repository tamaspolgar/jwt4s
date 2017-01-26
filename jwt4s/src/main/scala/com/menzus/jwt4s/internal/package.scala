package com.menzus.jwt4s

import java.nio.charset.StandardCharsets
import java.util.Base64

import cats.syntax.EitherSyntax
import com.menzus.jwt4s.error.Error
import com.menzus.jwt4s.error.InvalidBase64Format

import scala.util.Try

package object internal extends EitherSyntax {

  type Result[A] = Either[Error, A]

  val Base64Decoder = Base64.getUrlDecoder
  val Base64Encoder = Base64.getUrlEncoder.withoutPadding

  def asBase64(string: String) = {
    Base64Encoder.encodeToString(string.getBytes(StandardCharsets.UTF_8))
  }

  def extractBytesFromBase64(base64String: String): Result[Array[Byte]] = {
    Try(Base64Decoder.decode(base64String))
      .toEither.leftMap(_ => InvalidBase64Format(base64String))
  }

  def extractStringFromBase64(base64String: String): Result[String] = {
    extractBytesFromBase64(base64String)
      .map(bytes => new String(bytes, StandardCharsets.UTF_8))
  }
}
