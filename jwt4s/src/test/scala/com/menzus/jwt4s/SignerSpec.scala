package com.menzus.jwt4s

import org.scalatest.Matchers
import org.scalatest.WordSpec

class SignerSpec extends WordSpec with Matchers {

  "signTokenFor" should {

    "accept and extract payload from valid JWT" in {

      signer.signTokenFor("subject") shouldBe
        Token(
          idToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjEsImlhdCI6MH0." +
            "Uds5bROGidPvx0vQWqENj_6CSTSd7pXJVekugXK9A40",
          expiresIn = 1
        )
    }
  }

  val signer = Signer(DummySettings.signerSettings, DummyClock.fixedClock)
}
