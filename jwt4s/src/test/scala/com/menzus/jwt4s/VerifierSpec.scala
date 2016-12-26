package com.menzus.jwt4s

import com.menzus.jwt4s.error.ExpiredExpClaim
import com.menzus.jwt4s.error.FutureIatClaim
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidAudClaim
import com.menzus.jwt4s.error.InvalidIssClaim
import com.menzus.jwt4s.error.InvalidSignature
import com.menzus.jwt4s.internal.Claims
import com.menzus.jwt4s.internal.asBase64
import org.scalatest.Matchers
import org.scalatest.WordSpec

class VerifierSpec extends WordSpec with Matchers {

  "verifyAndExtractClaims" should {

    "accept and extract payload from valid JWT" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
        asBase64("""{"sub":"subject","aud":"audience","iss":"issuer","iat":-1,"exp":1,"roles":["admin"]}""") + "." +
        "qAqBsdNrNXx2LsEOcQvwhrxmVSn715MVzFQjjKKK1YA"
      ) shouldBe
        Right(
          Claims(
            iss = "issuer",
            sub = "subject",
            aud = "audience",
            exp = 1,
            iat = -1,
            roles = Set("admin")
          )
        )
    }

    "reject JWT with invalid signature" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"audience","iss":"issuer","iat":-1,"exp":1}""") + "." +
          "TWEAKED_0_klnp20CTexcAm_foJ9ET8ZELjar5exlsw"
      )  shouldBe
        Left(InvalidSignature)
    }

    "reject JWT with invalid issuer claim" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"audience","iss":"invalid issuer","iat":-1,"exp":1}""") + "." +
          "iTj561xPCI-ctiT9zzyj5OB86u5tEJFY7KHc8Dce42s"
      )  shouldBe
        Left(InvalidIssClaim("invalid issuer"))
    }

    "reject JWT with unsupported algorithm" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"RS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"audience","iss":"issuer","iat":-1,"exp":1}""") + "." +
          "notchecked"
      ) shouldBe
        Left(InvalidAlgHeader("RS256"))
    }

    "reject JWT with invalid audience claim" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"invalid audience","iss":"issuer","iat":-1,"exp":1}""") + "." +
          "notchecked"
      )  shouldBe
        Left(InvalidAudClaim("invalid audience"))
    }

    "reject JWT with expired exp" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"audience","iss":"issuer","iat":-3,"exp":-2}""") + "." +
          "notchecked"
      )  shouldBe
        Left(ExpiredExpClaim(-2, 0))
    }

    "reject JWT with future iat" in {

      verifier.verifyAndExtractClaims(
        asBase64("""{"alg":"HS256","typ":"JWT"}""") + "." +
          asBase64("""{"sub":"subject","aud":"audience","iss":"issuer","iat":2,"exp":3}""") + "." +
          "notchecked"
      )  shouldBe
        Left(FutureIatClaim(2, 0))
    }
  }

  val verifier = Verifier(DummySettings.verifierSettings)(DummyClock.fixedClock)
}
