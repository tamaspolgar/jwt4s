package com.menzus.jwt4s

import com.menzus.jwt4s.internal.Hs256
import com.menzus.jwt4s.internal.Hs384
import com.menzus.jwt4s.internal.Hs512

object DummySettings {

  val signerSettings = SignerSettings(

    hmacSecretKey = Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte), //base64(secret)
    algorithm = Hs256,
    audience = "audience",
    issuer = "issuer",
    expiresInS = 1
  )

  val verifierSettings = VerifierSettings(

    hmacSecretKey = Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte), //base64(secret)
    audience = "audience",
    issuer = "issuer",
    acceptedAlgHeaders = Set(Hs256, Hs384, Hs512),
    expToleranceInS = 1,
    iatToleranceInS = 1
  )
}
