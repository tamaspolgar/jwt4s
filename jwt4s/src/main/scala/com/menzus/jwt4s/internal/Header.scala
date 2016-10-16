package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.FailedToParseHeader
import com.menzus.jwt4s.error.InvalidTypInHeader
import com.menzus.jwt4s.error.UnacceptedAlgHeader
import com.menzus.jwt4s.error.UnacceptedFieldsInHeader
import com.menzus.jwt4s.internal.Algorithm.algHeaderToAlgorithm
import com.menzus.jwt4s.internal.Algorithm.algorithmToAlgHeader
import io.circe.Decoder
import io.circe.parser.decode

sealed trait Header
case class HsHeader(algorithm: Hs) extends Header

object Header {

  def asHeaderBase64(header: Header): String = header match {
    case HsHeader(alg) => asBase64(s"""{"alg":"${algorithmToAlgHeader(alg)}","typ":"JWT"}""")
  }

  def createHeader(alg: Algorithm): Header = {
    verifyAndExtractHeaderForAlg(alg)
  }

  def verifyAndExtractHeader(headerBase64: String)(implicit settings: VerifierSettings): Result[Header] = for {
    headerJson <- extractStringFromBase64(headerBase64)
    rawHeader  <- extractRawHeader(headerJson)
    _          <- verifyRawHeader(rawHeader, headerJson)
    alg        <- verifyAndExtractAlg(rawHeader.alg, settings.acceptedAlgHeaders)
    _          <- verifyAndExtractTyp(rawHeader.typ)
  } yield verifyAndExtractHeaderForAlg(alg)

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

  private def verifyAndExtractAlg(alg: String, acceptedAlgHeaders: Set[Algorithm]): Result[Algorithm] = for {
    alg <- algHeaderToAlgorithm(alg)
    _   <- rejectUnacceptedAlgs(alg, acceptedAlgHeaders)
  } yield alg

  private def rejectUnacceptedAlgs(alg: Algorithm, acceptedAlgHeaders: Set[Algorithm]) = {
    if (acceptedAlgHeaders.contains(alg)) {
      Xor.Right(alg)
    } else {
      Xor.Left(UnacceptedAlgHeader(alg))
    }
  }

  private def verifyAndExtractHeaderForAlg(alg: Algorithm): Header = alg match {
    case hs: Hs => HsHeader(hs)
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