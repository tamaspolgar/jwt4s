package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.Clock
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
import com.menzus.jwt4s.error.NoSubClaimProvided
import io.circe.Decoder
import io.circe.Json
import io.circe.parser.decode

case class Claims(
  iss: String,
  sub: String,
  aud: String,
  exp: Long,
  iat: Long,
  roles: Set[String] = Set.empty
)

object Payload {

  def createClaimsFor(subject: String, roles: Set[String])(implicit settings: SignerSettings, clock: Clock): String = {
    val nowInS = clock.nowInS

    val requiredClaims = Seq(
      "iss" -> Json.fromString(settings.issuer),
      "sub" -> Json.fromString(subject),
      "aud" -> Json.fromString(settings.audience),
      "exp" -> Json.fromLong(nowInS + settings.expiresInS),
      "iat" -> Json.fromLong(nowInS)
    )
    val rolesClaim =
      if (roles isEmpty) {
        Seq.empty
      } else {
        Seq("roles" -> Json.fromValues(roles.map(Json.fromString(_))))
      }

    val claims = Json.fromFields(requiredClaims ++ rolesClaim)

    asBase64(claims.noSpaces)
  }

  def verifyAndExtractClaims(payloadBase64: String)(implicit settings: VerifierSettings, clock: Clock): Result[Claims] = {
    val nowInS = clock.nowInS()

    for {
      claims <- decodeClaims(payloadBase64)
      iss    <- verifyIss(claims.iss, settings.issuer)
      sub    <- verifySub(claims.sub)
      aud    <- verifyAud(claims.aud, settings.audience)
      exp    <- verifyExp(claims.exp, settings.expToleranceInS, nowInS)
      iat    <- verifyIat(claims.iat, settings.iatToleranceInS, nowInS)
    } yield Claims(iss, sub, aud, exp, iat, claims.roles.getOrElse(Set.empty))
  }

  private case class RawClaims(
    iss: Option[String],
    sub: Option[String],
    aud: Option[String],
    exp: Option[Long],
    iat: Option[Long],
    roles: Option[Set[String]]
  )

  private implicit val claimsDecoder: Decoder[RawClaims] = Decoder.instance[RawClaims] { c =>
    for {
      iss   <- c.downField("iss").as[Option[String]]
      sub   <- c.downField("sub").as[Option[String]]
      aud   <- c.downField("aud").as[Option[String]]
      exp   <- c.downField("exp").as[Option[Long]]
      iat   <- c.downField("iat").as[Option[Long]]
      roles <- c.downField("roles").as[Option[Set[String]]]
    } yield RawClaims(iss, sub, aud, exp, iat, roles)
  }

  private def decodeClaims(payloadBase64: String): Result[RawClaims] = for {
    payload <- extractStringFromBase64(payloadBase64)
    claims  <- decode[RawClaims](payload).leftMap(_ => FailedToParseClaims(payload))
  } yield claims

  private def verifyIss(iss: Option[String], issuer: String): Result[String] = for {
    iss <- Xor.fromOption(iss, NoIssClaimProvided)
    _   <- Xor.fromOption(Some(iss).filter(_ == issuer), InvalidIssClaim(iss))
  } yield iss

  private def verifySub(sub: Option[String]): Result[String] = {
    Xor.fromOption(sub, NoSubClaimProvided)
  }

  private def verifyAud(aud: Option[String], audience: String): Result[String] = for {
    aud <- Xor.fromOption(aud, NoAudClaimProvided)
    _   <- Xor.fromOption(Some(aud).filter(_ == audience), InvalidAudClaim(aud))
  } yield aud

  private def verifyExp(exp: Option[Long], tolerance: Long, nowInS: Long): Result[Long] = for {
    exp <- Xor.fromOption(exp, NoExpClaimProvided)
    _   <- Xor.fromOption(Some(exp).filter(exp => nowInS <= (exp + tolerance)), ExpiredExpClaim(exp, nowInS))
  } yield exp

  private def verifyIat(iat: Option[Long], tolerance: Long, nowInS: Long): Result[Long] = for {
    iat <- Xor.fromOption(iat, NoIatClaimProvided)
    _   <- Xor.fromOption(Some(iat).filter(iat => (iat - tolerance) <= nowInS), FutureIatClaim(iat, nowInS))
  } yield iat
}
