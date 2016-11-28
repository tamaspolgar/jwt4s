package com.menzus.jwt4s.internal

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.menzus.jwt4s.SignerSettings
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidSignature

import scala.annotation.tailrec

sealed trait Algorithm

sealed abstract class Hs(javaMacAlgName: String) extends Algorithm {

  final def sign(message: String, hmacSecretKey: Array[Byte]): String = {
    val key = new SecretKeySpec(hmacSecretKey, javaMacAlgName)

    val mutableMac = Mac.getInstance(javaMacAlgName)
    mutableMac.init(key)
    mutableMac.update(bytesFromString(message))

    base64FromBytes(mutableMac.doFinal)
  }

  final def verify(message: String, providedSignatureBase64: String, hmacSecretKey: Array[Byte]): Result[String] = {
    val key = new SecretKeySpec(hmacSecretKey, javaMacAlgName)

    val mutableMac = Mac.getInstance(javaMacAlgName)
    mutableMac.init(key)
    mutableMac.update(bytesFromString(message))
    val calculatedSignatureBase64 = base64FromBytes(mutableMac.doFinal)

    if (secureDigestEquals(calculatedSignatureBase64, providedSignatureBase64)) {
      Right(providedSignatureBase64)
    } else {
      Left(InvalidSignature)
    }
  }

  private def bytesFromString(string: String): Array[Byte] = {
    string.getBytes(UTF8)
  }

  private def base64FromBytes(bytes: Array[Byte]): String = {
    Base64Encoder.encodeToString(bytes)
  }

  private def secureDigestEquals(s1: String, s2: String): Boolean = {

    @tailrec
    def secureDigestEquals(b1: Array[Byte], b2: Array[Byte], index: Int, acc: Int): Boolean = {
      if (index < b1.length) {
        secureDigestEquals(b1, b2, index + 1, acc | (b1(index) ^ b2(index)))
      } else {
        acc == 0
      }
    }

    val b1 = s1.getBytes(UTF8)
    val b2 = s2.getBytes(UTF8)

    if (b1.length == b2.length) {
      secureDigestEquals(b1, b2, 0, 0)
    } else {
      false
    }
  }
}

case object Hs256 extends Hs("HmacSHA256")
case object Hs384 extends Hs("HmacSHA384")
case object Hs512 extends Hs("HmacSHA512")

object Algorithm {

  def createSignature(header: Header, headerBase64: String, payloadBase64: String)(implicit settings: SignerSettings): String = {
    val unsignedToken = asUnsignedToken(headerBase64, payloadBase64)

    header match {
      case HsHeader(alg) => hsSign(alg, unsignedToken, settings.hmacSecretKey)
    }
  }

  def verifySignature(header: Header, headerBase64: String, payloadBase64: String, signatureBase64: String)(implicit settings: VerifierSettings): Result[String] = {
    val unsignedToken = asUnsignedToken(headerBase64, payloadBase64)

    header match {
      case HsHeader(alg) => hsVerify(alg, unsignedToken, signatureBase64, settings.hmacSecretKey)
    }
  }

  private[jwt4s] def algHeaderToAlgorithm(alg: String) = alg match {
    case "HS256" => Right(Hs256)
    case "HS384" => Right(Hs384)
    case "HS512" => Right(Hs512)
    case _       => Left(InvalidAlgHeader(alg))
  }

  private[jwt4s] def algorithmToAlgHeader(algorithm: Algorithm) = algorithm match {
    case Hs256 => "HS256"
    case Hs384 => "HS384"
    case Hs512 => "HS512"
  }

  private def asUnsignedToken(headerBase64: String, payloadBase64: String) = {
    List(headerBase64, payloadBase64).mkString(".")
  }

  private def hsVerify(hs: Hs, unsignedToken: String, signatureBase64: String, hsSecretKey: Array[Byte]) = {
    hs.verify(unsignedToken, signatureBase64, hsSecretKey)
  }

  private def hsSign(hs: Hs, unsignedToken: String, hsSecretKey: Array[Byte]) = {
    hs.sign(unsignedToken, hsSecretKey)
  }
}
