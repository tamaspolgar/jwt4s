package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.server.AuthorizationFailedRejection
import akka.http.scaladsl.server.Directive1
import akka.http.scaladsl.server.Directives.provide
import akka.http.scaladsl.server.Directives.reject
import akka.http.scaladsl.server.directives.AuthenticationDirective
import akka.http.scaladsl.server.directives.Credentials.Missing
import akka.http.scaladsl.server.directives.Credentials.Provided
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.menzus.jwt4s.Clock
import com.menzus.jwt4s.Verifier
import com.menzus.jwt4s.VerifierSettings
import com.menzus.jwt4s.internal.Claims

trait JwtDirectives {

  implicit val verifier: Verifier[Claims]

  def authorize(roles: String*): Directive1[Claims] = {
    authenticate.flatMap { claims =>
      if (roles.forall(role => claims.roles.contains(role))) {
        provide(claims)
      } else {
        reject(AuthorizationFailedRejection)
      }
    }
  }

  def authenticate: AuthenticationDirective[Claims] = {
    SecurityDirectives.authenticateOAuth2(
      realm = null,
      authenticator = {
        case Missing         => None
        case Provided(token) => verifier.verifyAndExtract(token).fold(
          error  => None,
          payload => Some(payload)
        )
      }
    )
  }
}

object JwtDirectives extends JwtDirectives {
  implicit val verifier = Verifier(VerifierSettings.fromConfig, Clock.systemClock)
}
