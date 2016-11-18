package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.model.headers.Authorization
import akka.http.scaladsl.model.headers.HttpChallenges.oAuth2
import akka.http.scaladsl.model.headers.OAuth2BearerToken
import akka.http.scaladsl.server.AuthenticationFailedRejection
import akka.http.scaladsl.server.AuthenticationFailedRejection.CredentialsMissing
import akka.http.scaladsl.server.AuthenticationFailedRejection.CredentialsRejected
import akka.http.scaladsl.server.AuthorizationFailedRejection
import akka.http.scaladsl.server.Directives._enhanceRouteWithConcatenation
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.Directives.get
import akka.http.scaladsl.server.Directives.path
import akka.http.scaladsl.testkit.ScalatestRouteTest
import cats.data.Xor
import com.menzus.jwt4s.Verifier
import com.menzus.jwt4s.error.InvalidSignature
import com.menzus.jwt4s.internal.Claims
import com.menzus.jwt4s.internal.Result
import org.scalatest.Matchers
import org.scalatest.WordSpec

class JwtDirectivesSpec extends WordSpec with Matchers with ScalatestRouteTest {

  "authenticate" should {

    "accept request with valid token" in {

      Get("/authenticated") ~>
        addHeader(Authorization(OAuth2BearerToken("noRole"))) ~>
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
  }

  "authorize" should {

    "accept request with valid token with the required role" in {

      Get("/authorized") ~>
        addHeader(Authorization(OAuth2BearerToken("withRole"))) ~>
        testRoute ~>
        check {
          status             shouldBe StatusCodes.OK
          responseAs[String] shouldBe "subject"
        }
    }

    "reject valid token without the required role" in {

      Get("/authorized") ~>
        addHeader(Authorization(OAuth2BearerToken("withOtherRole"))) ~>
        testRoute ~>
        check {
          rejection shouldBe AuthorizationFailedRejection
      }
    }
  }

  val testRoute =
    path("authenticated") {
      get {
        TestDirectives.authenticate { claims =>
          complete(claims.sub)
        }
      }
    } ~
    path("authorized") {
      get {
        TestDirectives.authorize("role") { claims =>
          complete(claims.sub)
        }
      }
    }

  object TestDirectives extends JwtDirectives {

    implicit val verifier = new Verifier[Claims] {

      override def verifyAndExtract(jwtToken: String): Result[Claims] = {
        val noRoles = Claims(
          iss = "issuer",
          sub = "subject",
          aud = "audience",
          exp = 0,
          iat = 0,
          roles = Set.empty
        )

        jwtToken match {
          case "withRole"      => Xor.Right(noRoles.copy(roles = Set("role")))
          case "withOtherRole" => Xor.Right(noRoles.copy(roles = Set("other-role")))
          case "noRole"        => Xor.Right(noRoles)
          case _               => Xor.Left(InvalidSignature)
        }
      }
    }
  }
}
