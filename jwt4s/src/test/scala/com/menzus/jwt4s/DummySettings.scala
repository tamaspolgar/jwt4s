package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Hs256
import com.menzus.jwt4s.internal.Hs384
import com.menzus.jwt4s.internal.Hs512

object DummySettings {

  val signerSettings = SignerSettings(

    hmacSecretKey =  internal.extractBytesFromBase64("secret").right.get,
    algorithm = Hs256,
    audience = "audience",
    issuer = "issuer",
    expiresInS = 1
  )

  val verifierSettings = VerifierSettings(

    hmacSecretKey = internal.extractBytesFromBase64("secret").right.get,
    audience = "audience",
    issuer = "issuer",
    acceptedAlgHeaders = Set(Hs256, Hs384, Hs512),
    expToleranceInS = 1,
    iatToleranceInS = 1,
    maxLifeTimeInS = 2
  )
}
