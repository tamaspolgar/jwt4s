package com.menzus.jwt4s

import java.nio.charset.Charset
import java.util.Base64

import cats.data.Xor
import com.menzus.jwt4s.error.Error
import com.menzus.jwt4s.error.InvalidBase64Format

import scala.util.Try

package object internal {

  type Result[A] = Xor[Error, A]

  val Base64Decoder = Base64.getUrlDecoder
  val Base64Encoder = Base64.getUrlEncoder.withoutPadding
  val UTF8 = Charset.forName("UTF-8")

  def asBase64(string: String) = {
    Base64Encoder.encodeToString(string.getBytes(UTF8))
  }

  def extractBytesFromBase64(base64String: String): Result[Array[Byte]] = {
    Xor.fromTry(Try(Base64Decoder.decode(base64String)))
      .leftMap(_ => InvalidBase64Format(base64String))
  }

  def extractStringFromBase64(base64String: String): Result[String] = {
    extractBytesFromBase64(base64String)
      .map(bytes => new String(bytes, UTF8))
  }
}
