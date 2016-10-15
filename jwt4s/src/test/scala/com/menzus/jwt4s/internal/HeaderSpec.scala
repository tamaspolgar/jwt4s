package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.DummySettings
import com.menzus.jwt4s.error.FailedToParseHeader
import com.menzus.jwt4s.error.InvalidAlgHeader
import com.menzus.jwt4s.error.InvalidBase64Format
import com.menzus.jwt4s.error.InvalidTypInHeader
import com.menzus.jwt4s.error.UnacceptedAlgHeader
import com.menzus.jwt4s.error.UnacceptedFieldsInHeader
import com.menzus.jwt4s.internal.Header.asHeaderBase64
import com.menzus.jwt4s.internal.Header.createHeader
import com.menzus.jwt4s.internal.Header.verifyAndExtractHeader
import org.scalatest.Matchers
import org.scalatest.WordSpec

class HeaderSpec extends WordSpec with Matchers {

  "verifyAndExtractHeader" should {

    implicit val settings = DummySettings.verifierSettings

    "accept header with supported algorithms" in {

      verifyAndExtractHeader(asBase64("""{"alg":"HS256","typ":"JWT"}""")) shouldBe Xor.Right(HsHeader(Hs256))
      verifyAndExtractHeader(asBase64("""{"alg":"HS384","typ":"JWT"}""")) shouldBe Xor.Right(HsHeader(Hs384))
      verifyAndExtractHeader(asBase64("""{"alg":"HS512","typ":"JWT"}""")) shouldBe Xor.Right(HsHeader(Hs512))
    }

    "reject header if it's not given in base64" in {

      verifyAndExtractHeader("non base64") shouldBe Xor.Left(InvalidBase64Format("non base64"))
    }

    "reject non valid json header" in {

      verifyAndExtractHeader(asBase64("invalid json")) shouldBe
        Xor.Left(FailedToParseHeader("invalid json"))

      verifyAndExtractHeader(asBase64("\"json string\"")) shouldBe
        Xor.Left(FailedToParseHeader("\"json string\""))

      verifyAndExtractHeader(asBase64("""{"typ":{},"alg":"HS256"}""")) shouldBe
        Xor.Left(FailedToParseHeader("""{"typ":{},"alg":"HS256"}"""))

      verifyAndExtractHeader(asBase64("""{"alg":{},"typ":"JWT"}""")) shouldBe
        Xor.Left(FailedToParseHeader("""{"alg":{},"typ":"JWT"}"""))

      verifyAndExtractHeader(asBase64("""{"typ":"JWT"}""")) shouldBe
        Xor.Left(FailedToParseHeader("""{"typ":"JWT"}"""))

      verifyAndExtractHeader(asBase64("""{"alg":"HS256"}""")) shouldBe
        Xor.Left(FailedToParseHeader("""{"alg":"HS256"}"""))
    }

    "reject header with unaccepted fields" in {

      verifyAndExtractHeader(asBase64("""{"alg":"anAlg","typ":"aTyp","unaccepted":"value"}""")) shouldBe
        Xor.Left(UnacceptedFieldsInHeader(Set("unaccepted")))
    }

    "reject header with unaccepted alg" in {

      val onlyHs384 = settings.copy(acceptedAlgHeaders = Set("HS256"))

      verifyAndExtractHeader(asBase64("""{"alg":"HS384","typ":"JWT"}"""))(onlyHs384) shouldBe
        Xor.Left(UnacceptedAlgHeader("HS384"))
    }

    "reject header with unsupported alg" in {

      val unsupported = settings.copy(acceptedAlgHeaders = Set("unsupported"))

      verifyAndExtractHeader(asBase64("""{"alg":"unsupported","typ":"JWT"}"""))(unsupported) shouldBe
        Xor.Left(InvalidAlgHeader("unsupported"))
    }

    "reject header with wrong typ field" in {

      verifyAndExtractHeader(asBase64("""{"alg":"HS256","typ":"non-JWT"}""")) shouldBe
        Xor.Left(InvalidTypInHeader("non-JWT"))
    }

    "createHeader" should {

      "create hs header for HS256" in {

        createHeader("HS256") shouldBe Xor.Right(HsHeader(Hs256))
      }

      "create hs header for HS384" in {

        createHeader("HS384") shouldBe Xor.Right(HsHeader(Hs384))
      }

      "create hs header for HS512" in {

        createHeader("HS512") shouldBe Xor.Right(HsHeader(Hs512))
      }

      "reject for unknown alg" in {

        createHeader("unknown") shouldBe Xor.Left(InvalidAlgHeader("unknown"))
      }
    }

    "createHeaderBase64" should {

      "encode the header" in {

        asHeaderBase64(HsHeader(Hs256)) shouldBe Xor.Right(asBase64("""{"alg":"HS256","typ":"JWT"}"""))
        asHeaderBase64(HsHeader(Hs384)) shouldBe Xor.Right(asBase64("""{"alg":"HS384","typ":"JWT"}"""))
        asHeaderBase64(HsHeader(Hs512)) shouldBe Xor.Right(asBase64("""{"alg":"HS512","typ":"JWT"}"""))
      }
    }
  }
}
