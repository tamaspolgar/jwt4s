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
import com.menzus.jwt4s.internal.Claims

object JwtDirectives {

  def authenticate(f: Claims => Route)(implicit verifier: Verifier[Claims]): Route = {
    authenticateDirective(verifier).apply(f)
  }

  def authorize(roles: String*)(f: Claims => Route)(implicit verifier: Verifier[Claims]): Route = {
    authenticateDirective(verifier)
      .flatMap(checkRoles(roles))
      .apply(f)
  }

  private def authenticateDirective(verifier: Verifier[Claims]) = {
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

  private def checkRoles(roles: Seq[String])(claims: Claims): Directive1[Claims] = {
    if (roles.forall(role => claims.roles.contains(role))) {
      provide(claims)
    } else {
      reject(AuthorizationFailedRejection)
    }
  }
}