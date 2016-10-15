package com.menzus.jwt4s

object DummySettings {

  val signerSettings = SignerSettings(

    hmacSecretKey = Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte), //base64(secret)
    algorithm = "HS256",
    audience = "audience",
    issuer = "issuer",
    maxAgeInS = 1
  )

  val verifierSettings = VerifierSettings(

    hmacSecretKey = Array[Int](0xB1, 0xE7, 0x2B, 0x7A).map(_.toByte), //base64(secret)
    audience = "audience",
    issuer = "issuer",
    acceptedAlgHeaders = Set("HS256", "HS384", "HS512"),
    expToleranceInS = 1,
    iatToleranceInS = 1,
    nbfToleranceInS = 1
  )
}
