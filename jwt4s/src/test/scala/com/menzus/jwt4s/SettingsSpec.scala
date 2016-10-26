package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Hs256
import com.typesafe.config.ConfigException.BadValue
import com.typesafe.config.ConfigFactory
import org.scalatest.Matchers
import org.scalatest.WordSpec

class SettingsSpec extends WordSpec with Matchers {

  "SignerSettings" should {

    "load settings from config" in {
      val signerSettings = SignerSettings()

      signerSettings.hmacSecretKey shouldBe Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte) //base64(secret)
      signerSettings.algorithm shouldBe Hs256
      signerSettings.audience shouldBe "theAudience"
      signerSettings.issuer shouldBe "theIssuer"
      signerSettings.expiresInS shouldBe 3600
    }

    "fail if the hmac secret is not a valid base 64 string" in {

      assertThrows[BadValue] {
        SignerSettings(
          ConfigFactory.parseString(
            """
              |jwt {
              |  hmac-secret-key-base64 = "non base 64 string"
              |}
            """.stripMargin
          ).withFallback(ConfigFactory.load())
        )
      }
    }

    "fail if the the algorithm is unsupported" in {

      assertThrows[BadValue] {
        SignerSettings(
          ConfigFactory.parseString(
            """
              |jwt {
              |  algorithm = "unsupported"
              |}
            """.stripMargin
          ).withFallback(ConfigFactory.load())
        )
      }
    }
  }

  "VerifierSettings" should {

    "load settings from config" in {

      val verifierSettings = VerifierSettings()

      verifierSettings.hmacSecretKey shouldBe Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte) //base64(secret)
      verifierSettings.audience shouldBe "theAudience"
      verifierSettings.issuer shouldBe "theIssuer"
      verifierSettings.acceptedAlgHeaders shouldBe Set(Hs256)
      verifierSettings.expToleranceInS shouldBe 60
      verifierSettings.iatToleranceInS shouldBe 60
    }

    "fail if the hmac secret is not a valid base 64 string" in {

      assertThrows[BadValue] {
        VerifierSettings(
          ConfigFactory.parseString(
            """
              |jwt {
              |  hmac-secret-key-base64 = "non base 64 string"
              |}
            """.stripMargin
          ).withFallback(ConfigFactory.load())
        )
      }
    }
  }
}