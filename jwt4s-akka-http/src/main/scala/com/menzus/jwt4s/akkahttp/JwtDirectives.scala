package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.server.AuthorizationFailedRejection
import akka.http.scaladsl.server.Directive1
import akka.http.scaladsl.server.Directives.provide
import akka.http.scaladsl.server.Directives.reject
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.server.directives.Credentials.Missing
import akka.http.scaladsl.server.directives.Credentials.Provided
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.menzus.jwt4s.Verifier
import com.menzus.jwt4s.internal.IdClaims

object JwtDirectives {

  def authenticate(f: IdClaims => Route)(implicit verifier: Verifier): Route = {
    authenticateDirective(verifier).apply(f)
  }

  def authorize(roles: String*)(f: IdClaims => Route)(implicit verifier: Verifier): Route = {
    authenticateDirective(verifier)
      .flatMap(checkRoles(roles))
      .apply(f)
  }

  private def authenticateDirective(verifier: Verifier) = {
    SecurityDirectives.authenticateOAuth2(
      realm = null,
      authenticator = {
        case Missing         => None
        case Provided(token) => verifier.verifyAndExtractIdClaims(token).fold(
          error  => None,
          payload => Some(payload)
        )
      }
    )
  }

  private def checkRoles(roles: Seq[String])(claims: IdClaims): Directive1[IdClaims] = {
    if (roles.forall(role => claims.roles.contains(role))) {
      provide(claims)
    } else {
      reject(AuthorizationFailedRejection)
    }
  }
}