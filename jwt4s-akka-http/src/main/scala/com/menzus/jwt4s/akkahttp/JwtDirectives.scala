package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.server.directives.AuthenticationDirective
import akka.http.scaladsl.server.directives.Credentials.Missing
import akka.http.scaladsl.server.directives.Credentials.Provided
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.menzus.jwt4s.Verifier

object JwtDirectives {

  def authenticate[A](verifier: Verifier[A], settings: Settings): AuthenticationDirective[A] = {
    SecurityDirectives.authenticateOAuth2[A](
      realm = settings.realm,
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