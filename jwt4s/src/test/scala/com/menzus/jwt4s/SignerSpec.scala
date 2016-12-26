package com.menzus.jwt4s

import org.scalatest.Matchers
import org.scalatest.WordSpec

class SignerSpec extends WordSpec with Matchers {

  "signSubject" should {

    "create a token for subject and roles" in {

      signer.signSubject("subject") shouldBe
        Token(
          idToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjEsImlhdCI6MH0." +
            "Uds5bROGidPvx0vQWqENj_6CSTSd7pXJVekugXK9A40",
          expiresIn = 1
        )
    }
  }

  "signSubjectAndRoles" should {

    "create a token for subject and roles" in {

      signer.signSubjectAndRoles("subject", Set("admin")) shouldBe
        Token(
          idToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjEsImlhdCI6MCwicm9sZXMiOlsiYWRtaW4iXX0." +
            "Dx1gDbUHBkWbUp5lHb3yDnF6T_icIqv2Eqan-gDMbAw",
          expiresIn = 1
        )
    }
  }

  val signer = Signer(DummySettings.signerSettings)(DummyClock.fixedClock)
}
