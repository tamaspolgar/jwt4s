package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.model.headers.Authorization
import akka.http.scaladsl.model.headers.HttpChallenges.oAuth2
import akka.http.scaladsl.model.headers.OAuth2BearerToken
import akka.http.scaladsl.server.AuthenticationFailedRejection
import akka.http.scaladsl.server.AuthenticationFailedRejection.CredentialsMissing
import akka.http.scaladsl.server.AuthenticationFailedRejection.CredentialsRejected
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.Directives.get
import akka.http.scaladsl.server.Directives.path
import akka.http.scaladsl.testkit.ScalatestRouteTest
import cats.data.Xor
import com.menzus.jwt4s.Verifier
import com.menzus.jwt4s.akkahttp.JwtDirectives.authenticate
import com.menzus.jwt4s.error.InvalidSignature
import com.menzus.jwt4s.internal.Result
import org.scalatest.Matchers
import org.scalatest.WordSpec

class JwtDirectivesSpec extends WordSpec with Matchers with ScalatestRouteTest {

  "authenticateJwt" should {

    "accept request with valid token" in {

      Get("/authenticated") ~>
        addHeader(Authorization(OAuth2BearerToken("valid"))) ~>
        testRoute ~>
        check {
          status             shouldBe StatusCodes.OK
          responseAs[String] shouldBe "subject"
        }
    }

    "reject request without token in Authorization header" in {

      Get("/authenticated") ~>
        testRoute ~>
        check {
          rejection shouldBe AuthenticationFailedRejection(CredentialsMissing, oAuth2(null))
      }
    }

    "reject request incorrect token in Authorization header" in {

      Get("/authenticated") ~>
        addHeader("Authorization", "incorrect bearer") ~>
        testRoute ~>
        check {
          rejection shouldBe AuthenticationFailedRejection(CredentialsRejected, oAuth2(null))
      }
    }

    "reject request incorrect bearer token in Authorization header" in {

      Get("/authenticated") ~>
        addHeader(Authorization(OAuth2BearerToken("invalid"))) ~>
        testRoute ~>
        check {
          rejection shouldBe AuthenticationFailedRejection(CredentialsRejected, oAuth2(null))
      }
    }

    def testRoute =
      path("authenticated") {
        get {
          authenticate(verifier) { payload =>
            complete(payload)
          }
        }
      }
  }

  private val verifier = new Verifier[String] {
    override def verifyAndExtract(jwtToken: String): Result[String] = {
      if (jwtToken == "valid") {
        Xor.Right("subject")
      } else {
        Xor.Left(InvalidSignature)
      }
    }
  }
}
