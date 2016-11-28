package com.menzus.jwt4s.internal

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
import com.menzus.jwt4s.error.NoRfpClaimProvided
import com.menzus.jwt4s.error.NoSubClaimProvided
import com.menzus.jwt4s.internal.Payload.createIdClaimsFor
import com.menzus.jwt4s.internal.Payload.createRfpClaimsFor
import com.menzus.jwt4s.internal.Payload.verifyAndExtractIdClaims
import com.menzus.jwt4s.internal.Payload.verifyAndExtractRfpClaims
import org.scalatest.Matchers
import org.scalatest.WordSpec

class ClaimsSpec extends WordSpec with Matchers {

  implicit val clock = DummyClock.fixedClock
  implicit val signerSettings = DummySettings.signerSettings
  implicit val verifierSettings = DummySettings.verifierSettings

  "createIdClaimsFor" should {

    "create id claims for the subject and roles" in {

      createIdClaimsFor("subject", Set("admin")) shouldBe
        asBase64("""{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"iat":0,"roles":["admin"]}""")
    }

    "create id claims for the subject without roles" in {

      createIdClaimsFor("subject", Set.empty) shouldBe
        asBase64("""{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"iat":0}""")
    }
  }

  "createRfpClaimsFor" should {

    "create rfp claims for the rfp token" in {

      createRfpClaimsFor("rfp token") shouldBe
        asBase64("""{"iss":"issuer","rfp":"rfp token","aud":"audience","exp":1,"iat":0}""")
    }
  }

  "verifyAndExtractIdClaims" should {

    "accept and return valid claims" in {

      verifyAndExtractIdClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus1,"exp":$TPlus1,"roles":["role1","role2"]}""")
      ) shouldBe Right(
        IdClaims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TPlus1,
          iat = TMinus1,
          roles = Set("role1", "role2")
        )
      )
    }

    "accept iat within the tolerance" in {

      verifyAndExtractIdClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TPlus1,"exp":$TPlus2}""")
      ) shouldBe Right(
        IdClaims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TPlus2,
          iat = TPlus1,
          roles = Set.empty
        )
      )
    }


    "accept exp within the tolerance" in {

      verifyAndExtractIdClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus2,"exp":$TMinus1}""")
      ) shouldBe Right(
        IdClaims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = TMinus1,
          iat = TMinus2,
          roles = Set.empty
        )
      )
    }

    "reject invalid json claims" in {

      verifyAndExtractIdClaims(asBase64(s"""not json""")) shouldBe Left(FailedToParseClaims("""not json"""))
    }

    "reject non base64 payload" in {

      verifyAndExtractIdClaims("non base64") shouldBe Left(InvalidBase64Format("non base64"))
    }

    "reject header with missing subject" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"audience","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Left(NoSubClaimProvided)
    }

    "reject header with missing audience" in {

      verifyAndExtractIdClaims(asBase64(s"""{"sub":"subject","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Left(NoAudClaimProvided)
    }

    "reject header with wrong audience" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"other audience","sub":"subject","iss":"issuer","iat":-1,"exp":1}""")) shouldBe
        Left(InvalidAudClaim("other audience"))
    }

    "reject header with missing issuer" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"audience","sub":"subject","iat":-1,"exp":1}""")) shouldBe
        Left(NoIssClaimProvided)
    }

    "reject header with wrong issuer" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"other issuer","iat":-1,"exp":1}""")) shouldBe
        Left(InvalidIssClaim("other issuer"))
    }

    "reject header with missing exp" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":-1}""")) shouldBe
        Left(NoExpClaimProvided)
    }

    "reject header with out of tolerance expired exp" in {

      verifyAndExtractIdClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TMinus3,"exp":$TMinus2}""")) shouldBe
        Left(ExpiredExpClaim(TMinus2, T0))
    }

    "reject header with missing iat" in {

      verifyAndExtractIdClaims(asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","exp":$TPlus1}""")) shouldBe
        Left(NoIatClaimProvided)
    }

    "reject header with out of tolerance future iat" in {

      verifyAndExtractIdClaims(
        asBase64(s"""{"aud":"audience","sub":"subject","iss":"issuer","iat":$TPlus2,"exp":$TPlus3}""")) shouldBe
        Left(FutureIatClaim(TPlus2, T0))
    }
  }

  "verifyAndExtractRfpClaims" should {

    "accept and return valid claims" in {

      verifyAndExtractRfpClaims(
        asBase64(s"""{"aud":"audience","rfp":"rfp token","iss":"issuer","iat":$TMinus1,"exp":$TPlus1}""")
      ) shouldBe Right(
        RfpClaims(
          iss = "issuer",
          rfp = "rfp token",
          aud = "audience",
          exp = TPlus1,
          iat = TMinus1
        )
      )
    }

    "reject with missing rfp claim" in {

      verifyAndExtractRfpClaims(
        asBase64(s"""{"aud":"audience","iss":"issuer","iat":$TMinus1,"exp":$TPlus1}""")
      ) shouldBe Left(NoRfpClaimProvided)
    }

    "reject invalid json claims" in {

      verifyAndExtractRfpClaims(asBase64(s"""not json""")) shouldBe Left(FailedToParseClaims("""not json"""))
    }
  }

  val TMinus3 = -3
  val TMinus2 = -2
  val TMinus1 = -1
  val T0      = 0
  val TPlus1  = 1
  val TPlus2  = 2
  val TPlus3  = 3
}