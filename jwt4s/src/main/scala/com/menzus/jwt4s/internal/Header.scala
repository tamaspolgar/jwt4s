package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.FailedToParseHeader
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidTypInHeader
import com.menzus.jwt4s.error.UnacceptedAlgHeader
import com.menzus.jwt4s.error.UnacceptedFieldsInHeader
import io.circe.Decoder
import io.circe.parser.decode

sealed trait Header
case class HsHeader(algorithm: Hs) extends Header

object Header {

  def createHeader(alg: String): Result[Header] = for {
    alg    <- algHeaderToAlgorithm(alg)
    header <- verifyAndExtractHeaderForAlg(alg)
  } yield header

  def asHeaderBase64(header: Header): Result[String] = header match {
    case HsHeader(alg) => Xor.Right(asBase64(s"""{"alg":"${algorithmToAlgHeader(alg)}","typ":"JWT"}"""))
  }

  def verifyAndExtractHeader(headerBase64: String)(implicit settings: VerifierSettings): Result[Header] = for {
    headerJson <- extractStringFromBase64(headerBase64)
    rawHeader  <- extractRawHeader(headerJson)
    _          <- verifyRawHeader(rawHeader, headerJson)
    alg        <- verifyAndExtractAlg(rawHeader.alg, settings.acceptedAlgHeaders)
    _          <- verifyAndExtractTyp(rawHeader.typ)
    header     <- verifyAndExtractHeaderForAlg(alg)
  } yield header

  private case class RawHeader(alg: String, typ: String, fields: Set[String])

  private implicit val rawHeaderDecoder = Decoder.instance[RawHeader] { c =>
    for {
      alg <- c.downField("alg").as[String]
      typ <- c.downField("typ").as[String]
    } yield RawHeader(alg, typ, c.fieldSet.get)
  }

  private def extractRawHeader(headerJson: String) = {
    decode[RawHeader](headerJson).leftMap(_ => FailedToParseHeader(headerJson))
  }

  private def verifyRawHeader(rawHeader: RawHeader, headerJson: String): Result[RawHeader] = for {
    _ <- rejectUnacceptedFields(rawHeader.fields)
  } yield rawHeader

  private def verifyAndExtractTyp(typ: String): Result[String] = typ match {
    case "JWT" => Xor.Right(typ)
    case _     => Xor.Left(InvalidTypInHeader(typ))
  }

  private def verifyAndExtractAlg(alg: String, acceptedAlgHeaders: Set[String]): Result[Algorithm] = for {
    _         <- rejectUnacceptedAlgs(alg, acceptedAlgHeaders)
    algorithm <- algHeaderToAlgorithm(alg)
  } yield algorithm

  private def rejectUnacceptedAlgs(alg: String, acceptedAlgHeaders: Set[String]) = {
    if (acceptedAlgHeaders.contains(alg)) {
      Xor.Right(alg)
    } else {
      Xor.Left(UnacceptedAlgHeader(alg))
    }
  }

  private def algHeaderToAlgorithm(alg: String) = alg match {
    case "HS256" => Xor.Right(Hs256)
    case "HS384" => Xor.Right(Hs384)
    case "HS512" => Xor.Right(Hs512)
    case _       => Xor.Left(InvalidAlgHeader(alg))
  }

  private def algorithmToAlgHeader(algorithm: Algorithm) = algorithm match {
    case Hs256 => "HS256"
    case Hs384 => "HS384"
    case Hs512 => "HS512"
  }

  private def verifyAndExtractHeaderForAlg(alg: Algorithm): Result[Header] = alg match {
    case hs: Hs => Xor.Right(HsHeader(hs))
  }

  private val AcceptedFields = Set("alg", "typ")

  private def rejectUnacceptedFields(fields: Set[String]) = {
    val unacceptedFields = fields.filterNot(field => AcceptedFields.contains(field))
    if (unacceptedFields.isEmpty) {
      Xor.Right(unacceptedFields)
    } else {
      Xor.Left(UnacceptedFieldsInHeader(unacceptedFields))
    }
  }
}