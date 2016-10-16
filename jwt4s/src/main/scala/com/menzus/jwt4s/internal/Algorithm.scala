package com.menzus.jwt4s.internal

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import cats.data.Xor
import com.menzus.jwt4s.SignerSettings
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidSignature

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

    if (calculatedSignatureBase64 == providedSignatureBase64) {
      Xor.Right(providedSignatureBase64)
    } else {
      Xor.Left(InvalidSignature)
    }
  }

  private def bytesFromString(string: String): Array[Byte] = {
    string.getBytes(UTF8)
  }

  private def base64FromBytes(bytes: Array[Byte]): String = {
    Base64Encoder.encodeToString(bytes)
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
    case "HS256" => Xor.Right(Hs256)
    case "HS384" => Xor.Right(Hs384)
    case "HS512" => Xor.Right(Hs512)
    case _       => Xor.Left(InvalidAlgHeader(alg))
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
