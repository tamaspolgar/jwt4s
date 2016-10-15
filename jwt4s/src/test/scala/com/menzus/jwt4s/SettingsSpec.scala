package com.menzus.jwt4s

import com.typesafe.config.ConfigException.BadValue
import com.typesafe.config.ConfigFactory
import org.scalatest.Matchers
import org.scalatest.WordSpec

class SettingsSpec extends WordSpec with Matchers {

  "SignerSettings" should {

    "load settings from config" in {
      val signerSettings = SignerSettings()

      signerSettings.hmacSecretKey shouldBe Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte) //base64(secret)
      signerSettings.algorithm shouldBe "algorithm"
      signerSettings.audience shouldBe "theAudience"
      signerSettings.issuer shouldBe "theIssuer"
      signerSettings.maxAgeInS shouldBe 60
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
          )
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
      verifierSettings.acceptedAlgHeaders shouldBe Set("alg1")
      verifierSettings.expToleranceInS shouldBe 60
      verifierSettings.iatToleranceInS shouldBe 60
      verifierSettings.nbfToleranceInS shouldBe 60
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
          )
        )
      }
    }
  }
}