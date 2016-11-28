package com.menzus.jwt4s.internal

import java.time.Clock

import com.menzus.jwt4s.SignerSettings
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.error.ExpiredExpClaim
import com.menzus.jwt4s.error.FailedToParseClaims
import com.menzus.jwt4s.error.FutureIatClaim
import com.menzus.jwt4s.error.InvalidAudClaim
import com.menzus.jwt4s.error.InvalidIssClaim
import com.menzus.jwt4s.error.NoAudClaimProvided
import com.menzus.jwt4s.error.NoExpClaimProvided
import com.menzus.jwt4s.error.NoIatClaimProvided
import com.menzus.jwt4s.error.NoIssClaimProvided
import com.menzus.jwt4s.error.NoRfpClaimProvided
import com.menzus.jwt4s.error.NoSubClaimProvided
import io.circe.Decoder
import io.circe.Json
import io.circe.parser.decode

case class IdClaims(
  iss: String,
  sub: String,
  aud: String,
  exp: Long,
  iat: Long,
  roles: Set[String] = Set.empty
)

case class RfpClaims(
  iss: String,
  rfp: String,
  aud: String,
  exp: Long,
  iat: Long
)

object Payload {

  def createIdClaimsFor(sub: String, roles: Set[String])(implicit settings: SignerSettings, clock: Clock): String = {
    val nowInS = clock.instant.getEpochSecond

    val requiredClaims = Seq(
      "iss" -> Json.fromString(settings.issuer),
      "sub" -> Json.fromString(sub),
      "aud" -> Json.fromString(settings.audience),
      "exp" -> Json.fromLong(nowInS + settings.expiresInS),
      "iat" -> Json.fromLong(nowInS)
    )
    val rolesClaim =
      if (roles.isEmpty) {
        Seq.empty
      } else {
        Seq("roles" -> Json.fromValues(roles.map(Json.fromString(_))))
      }

    val idClaims = Json.fromFields(requiredClaims ++ rolesClaim)

    asBase64(idClaims.noSpaces)
  }

  def createRfpClaimsFor(rfp: String)(implicit settings: SignerSettings, clock: Clock): String = {
    val nowInS = clock.instant.getEpochSecond

    val rfpClaims = Json.obj(
      "iss" -> Json.fromString(settings.issuer),
      "rfp" -> Json.fromString(rfp),
      "aud" -> Json.fromString(settings.audience),
      "exp" -> Json.fromLong(nowInS + settings.expiresInS),
      "iat" -> Json.fromLong(nowInS)
    )

    asBase64(rfpClaims.noSpaces)
  }

  def verifyAndExtractIdClaims(payloadBase64: String)(implicit settings: VerifierSettings, clock: Clock): Result[IdClaims] = {
    val nowInS = clock.instant.getEpochSecond

    for {
      claims <- decodeIdClaims(payloadBase64)
      iss    <- verifyIss(claims.iss, settings.issuer)
      sub    <- verifySub(claims.sub)
      aud    <- verifyAud(claims.aud, settings.audience)
      exp    <- verifyExp(claims.exp, settings.expToleranceInS, nowInS)
      iat    <- verifyIat(claims.iat, settings.iatToleranceInS, nowInS)
    } yield IdClaims(iss, sub, aud, exp, iat, claims.roles.getOrElse(Set.empty))
  }

  def verifyAndExtractRfpClaims(payloadBase64: String)(implicit settings: VerifierSettings, clock: Clock): Result[RfpClaims] = {
    val nowInS = clock.instant.getEpochSecond

    for {
      claims <- decodeRfpClaims(payloadBase64)
      iss    <- verifyIss(claims.iss, settings.issuer)
      rfp    <- verifyRfp(claims.rfp)
      aud    <- verifyAud(claims.aud, settings.audience)
      exp    <- verifyExp(claims.exp, settings.expToleranceInS, nowInS)
      iat    <- verifyIat(claims.iat, settings.iatToleranceInS, nowInS)
    } yield RfpClaims(iss, rfp, aud, exp, iat)
  }

  private case class RawIdClaims(
    iss: Option[String],
    sub: Option[String],
    aud: Option[String],
    exp: Option[Long],
    iat: Option[Long],
    roles: Option[Set[String]]
  )

  private case class RawRfpClaims(
    iss: Option[String],
    rfp: Option[String],
    aud: Option[String],
    exp: Option[Long],
    iat: Option[Long]
  )

  private implicit val idClaimsDecoder: Decoder[RawIdClaims] = Decoder.instance[RawIdClaims] { c =>
    for {
      iss   <- c.downField("iss").as[Option[String]]
      sub   <- c.downField("sub").as[Option[String]]
      aud   <- c.downField("aud").as[Option[String]]
      exp   <- c.downField("exp").as[Option[Long]]
      iat   <- c.downField("iat").as[Option[Long]]
      roles <- c.downField("roles").as[Option[Set[String]]]
    } yield RawIdClaims(iss, sub, aud, exp, iat, roles)
  }

  private implicit val rfpClaimsDecoder: Decoder[RawRfpClaims] = Decoder.instance[RawRfpClaims] { c =>
    for {
      iss   <- c.downField("iss").as[Option[String]]
      rfp   <- c.downField("rfp").as[Option[String]]
      aud   <- c.downField("aud").as[Option[String]]
      exp   <- c.downField("exp").as[Option[Long]]
      iat   <- c.downField("iat").as[Option[Long]]
    } yield RawRfpClaims(iss, rfp, aud, exp, iat)
  }

  private def decodeIdClaims(payloadBase64: String): Result[RawIdClaims] = for {
    payload <- extractStringFromBase64(payloadBase64)
    claims  <- decode[RawIdClaims](payload).leftMap(_ => FailedToParseClaims(payload))
  } yield claims

  private def decodeRfpClaims(payloadBase64: String): Result[RawRfpClaims] = for {
    payload <- extractStringFromBase64(payloadBase64)
    claims  <- decode[RawRfpClaims](payload).leftMap(_ => FailedToParseClaims(payload))
  } yield claims

  private def verifyIss(iss: Option[String], issuer: String): Result[String] = for {
    iss <- iss.toRight(NoIssClaimProvided)
    _   <- Some(iss).filter(_ == issuer).toRight(InvalidIssClaim(iss))
  } yield iss

  private def verifySub(sub: Option[String]): Result[String] = {
    sub.toRight(NoSubClaimProvided)
  }

  private def verifyRfp(rfp: Option[String]): Result[String] = {
    rfp.toRight(NoRfpClaimProvided)
  }

  private def verifyAud(aud: Option[String], audience: String): Result[String] = for {
    aud <- aud.toRight(NoAudClaimProvided)
    _   <- Some(aud).filter(_ == audience).toRight(InvalidAudClaim(aud))
  } yield aud

  private def verifyExp(exp: Option[Long], tolerance: Long, nowInS: Long): Result[Long] = for {
    exp <- exp.toRight(NoExpClaimProvided)
    _   <- Some(exp).filter(exp => nowInS <= (exp + tolerance)).toRight(ExpiredExpClaim(exp, nowInS))
  } yield exp

  private def verifyIat(iat: Option[Long], tolerance: Long, nowInS: Long): Result[Long] = for {
    iat <- iat.toRight(NoIatClaimProvided)
    _   <- Some(iat).filter(iat => (iat - tolerance) <= nowInS).toRight(FutureIatClaim(iat, nowInS))
  } yield iat
}
