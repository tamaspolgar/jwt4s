package com.menzus.jwt4s.internal

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.menzus.jwt4s.SignerSettings
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidSignature

sealed trait Algorithm

sealed abstract class Hs(javaMacAlgName: String) extends Algorithm {

  def sign(message: String, hmacSecretKey: Array[Byte]): String = {
    val key = new SecretKeySpec(hmacSecretKey, javaMacAlgName)

    val mutableMac = Mac.getInstance(javaMacAlgName)
    mutableMac.init(key)
    mutableMac.update(bytesFromUTF8String(message))

    base64FromBytes(mutableMac.doFinal)
  }

  def verify(message: String, providedSignatureBase64: String, hmacSecretKey: Array[Byte]): Result[String] = {
    for {
      signature <- extractSignatureBytes(providedSignatureBase64)
      _         <- verify(message, signature, hmacSecretKey)
    } yield providedSignatureBase64
  }

  private def extractSignatureBytes(providedSignatureBase64: String) = {
    extractBytesFromBase64(providedSignatureBase64)
      .leftMap(_ => InvalidSignature)
  }

  private def verify(message: String, providedSignature: Array[Byte], hmacSecretKey: Array[Byte]): Result[Array[Byte]] = {
    val key = new SecretKeySpec(hmacSecretKey, javaMacAlgName)

    val mutableMac = Mac.getInstance(javaMacAlgName)
    mutableMac.init(key)
    mutableMac.update(bytesFromUTF8String(message))
    val calculatedSignature = mutableMac.doFinal

    if (MessageDigest.isEqual(calculatedSignature, providedSignature)) {
      Right(providedSignature)
    } else {
      Left(InvalidSignature)
    }
  }

  private def base64FromBytes(bytes: Array[Byte]): String = {
    Base64Encoder.encodeToString(bytes)
  }

  private def bytesFromUTF8String(string: String): Array[Byte] = {
    string.getBytes(UTF8)
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

  def verifySignature(header: Header, headerBase64: String, payloadBase64: String, providedSignatureBase64: String)(implicit settings: VerifierSettings): Result[String] = {
    val unsignedToken = asUnsignedToken(headerBase64, payloadBase64)

    header match {
      case HsHeader(alg) => hsVerify(alg, unsignedToken, providedSignatureBase64, settings.hmacSecretKey)
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

  private def hsVerify(hs: Hs, unsignedToken: String, providedSignatureBase64: String, hsSecretKey: Array[Byte]) = {
    hs.verify(unsignedToken, providedSignatureBase64, hsSecretKey)
  }

  private def hsSign(hs: Hs, unsignedToken: String, hsSecretKey: Array[Byte]) = {
    hs.sign(unsignedToken, hsSecretKey)
  }
}
