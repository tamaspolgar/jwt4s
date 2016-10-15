package com.menzus.jwt4s.error

sealed trait Error

case object InvalidStructure extends Error
case class InvalidBase64Format(invalidString: String) extends Error

case class FailedToParseHeader(header: String) extends Error
case class UnacceptedFieldsInHeader(unacceptedFields: Set[String]) extends Error

case class InvalidTypInHeader(typ: String) extends Error
case class UnacceptedAlgHeader(alg: String) extends Error
case class InvalidAlgHeader(alg: String) extends Error

case object InvalidSignature extends Error

case class FailedToParseClaims(claims: String) extends Error

case object NoSubClaimProvided extends Error

case object NoAudClaimProvided extends Error
case class InvalidAudClaim(aud: String) extends Error

case object NoIssClaimProvided extends Error
case class InvalidIssClaim(iss: String) extends Error

case object NoExpClaimProvided extends Error
case class ExpiredExpClaim(exp: Long, current: Long) extends Error

case object NoIatClaimProvided extends Error
case class FutureIatClaim(iat: Long, current: Long) extends Error

case object NoNbfClaimProvided extends Error
case class FutureNbfClaim(nbf: Long, current: Long) extends Error

case class FailedToParsePayload(payload: String) extends Error