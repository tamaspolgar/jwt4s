package com.menzus.jwt4s

import org.scalatest.Matchers
import org.scalatest.WordSpec

class SignerSpec extends WordSpec with Matchers {

  "signTokenFor" should {

    "accept and extract payload from valid JWT" in {

      signer.signTokenFor("subject") shouldBe
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjEsIm5iZiI6MCwiaWF0IjowfQ." +
        "ob2Cmk82Ak6Guq2AflmyzRe7snTal8JREMhZQj6mwyM"
    }
  }

  val signer = Signer(DummySettings.signerSettings, DummyClock.fixedClock)
}
