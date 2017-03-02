package com.menzus.jwt4s.akkahttp

import akka.http.scaladsl.server.AuthorizationFailedRejection
import akka.http.scaladsl.server.Rejection
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.server.directives.Credentials.Missing
import akka.http.scaladsl.server.directives.Credentials.Provided
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.menzus.jwt4s.Verifier
import com.menzus.jwt4s.internal.Claims

object JwtDirectives {
// todo this returns a plain/text response, it would be nice to customize it, maybe with rejection handler
  def authenticate(f: Claims => Route)(implicit verifier: Verifier): Route = {
    authenticateDirective(verifier).apply(f)
  }

  def authorizeRoles(roles: String*)(f: Claims => Route)(implicit verifier: Verifier): Route = {
    filter(rolesFilter(roles), AuthorizationFailedRejection)(f)
  }

  private def filter(predicate: Claims ⇒ Boolean, rejections: Rejection*)(f: Claims => Route)(implicit verifier: Verifier): Route = {
    authenticateDirective(verifier)
      .filter(predicate, rejections: _*)
      .apply(f)
  }

  private def authenticateDirective(verifier: Verifier) = {
    SecurityDirectives.authenticateOAuth2(
      realm = null,
      authenticator = {
        case Missing         => None
        case Provided(token) => verifier.verifyAndExtractClaims(token).fold(
          error  => None,
          payload => Some(payload)
        )
      }
    )
  }

  private def rolesFilter(roles: Seq[String])(claims: Claims): Boolean = {
    roles.forall(role => claims.roles.contains(role))
  }
}