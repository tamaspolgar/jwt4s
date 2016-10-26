package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.DummyClock
import com.menzus.jwt4s.DummySettings
import com.menzus.jwt4s.error.ExpiredExpClaim
import com.menzus.jwt4s.error.FailedToParseClaims
import com.menzus.jwt4s.error.FutureIatClaim
import com.menzus.jwt4s.error.InvalidAudClaim
import com.menzus.jwt4s.error.InvalidBase64Format
import com.menzus.jwt4s.error.InvalidIssClaim
import com.menzus.jwt4s.error.NoAudClaimProvided
import com.menzus.jwt4s.error.NoExpClaimProvided
import com.menzus.jwt4s.error.NoIatClaimProvided
import com.menzus.jwt4s.error.NoIssClaimProvided
import com.menzus.jwt4s.error.NoSubClaimProvided
import com.menzus.jwt4s.internal.Payload.createClaimsFor
import com.menzus.jwt4s.internal.Payload.verifyAndExtractClaims
import org.scalatest.Matchers
import org.scalatest.WordSpec

class ClaimsSpec extends WordSpec with Matchers {

  "createClaimsJsonFor" should {

    "create claims for the subject and the verifier config" in {

      createClaimsFor("subject") shouldBe
        asBase64("""{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"iat":0}""")
    }
  }

  "verifyAndExtractClaims" should {

    "accept and return valid claims" in {

      verifyAndExtractClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus1,"exp":$TPlus1}""")
      ) shouldBe Xor.Right(
        Claims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TPlus1,
          iat = TMinus1
        )
      )
    }

    "accept iat within the tolerance" in {

      verifyAndExtractClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TPlus1,"exp":$TPlus2}""")
      ) shouldBe Xor.Right(
        Claims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TPlus2,
          iat = TPlus1
        )
      )
    }


    "accept exp within the tolerance" in {

      verifyAndExtractClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus2,"exp":$TMinus1}""")
      ) shouldBe Xor.Right(
        Claims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TMinus1,
          iat = TMinus2
        )
      )
    }

    "reject invalid json claims" in {

      verifyAndExtractClaims(asBase64(s"""not json""")) shouldBe Xor.Left(FailedToParseClaims("""not json"""))
    }

    "reject non base64 payload" in {

      verifyAndExtractClaims("non base64") shouldBe Xor.Left(InvalidBase64Format("non base64"))
    }

    "reject header with missing subject" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"audience","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Xor.Left(NoSubClaimProvided)
    }

    "reject header with missing audience" in {

      verifyAndExtractClaims(asBase64(s"""{"sub":"subject","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Xor.Left(NoAudClaimProvided)
    }

    "reject header with wrong audience" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"other audience","sub":"subject","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Xor.Left(InvalidAudClaim("other audience"))
    }

    "reject header with missing issuer" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"audience","sub":"subject","iat":-1,"exp":1}""")) shouldBe
        Xor.Left(NoIssClaimProvided)
    }

    "reject header with wrong issuer" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"other issuer","iat":-1,"exp":1}""")) shouldBe
        Xor.Left(InvalidIssClaim("other issuer"))
    }

    "reject header with missing exp" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":-1}""")) shouldBe
        Xor.Left(NoExpClaimProvided)
    }

    "reject header with out of tolerance expired exp" in {

      verifyAndExtractClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus3,"exp":$TMinus2}""")) shouldBe
        Xor.Left(ExpiredExpClaim(TMinus2, T0))
    }

    "reject header with missing iat" in {

      verifyAndExtractClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","exp":$TPlus1}""")) shouldBe
        Xor.Left(NoIatClaimProvided)
    }

    "reject header with out of tolerance future iat" in {

      verifyAndExtractClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TPlus2,"exp":$TPlus3}""")) shouldBe
        Xor.Left(FutureIatClaim(TPlus2, T0))
    }
  }

  implicit val clock = DummyClock.fixedClock
  implicit val signerSettings = DummySettings.signerSettings
  implicit val verifierSettings = DummySettings.verifierSettings

  val TMinus3 = -3
  val TMinus2 = -2
  val TMinus1 = -1
  val T0      = 0
  val TPlus1  = 1
  val TPlus2  = 2
  val TPlus3  = 3
}