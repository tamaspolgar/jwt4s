package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.DummyClock
import com.menzus.jwt4s.DummySettings
import com.menzus.jwt4s.error
import com.menzus.jwt4s.internal.Algorithm.createSignature
import com.menzus.jwt4s.internal.Algorithm.verifySignature
import org.scalatest.Matchers
import org.scalatest.WordSpec

class HSAlgorithmSpec extends WordSpec with Matchers {

  "createSignature" should {

    "create valid HS256 signature" in {

      createSignature(
        HsHeader(Hs256),
        Hs256Header,
        Payload
      ) shouldBe ValidSignatureHS256
    }

    "create valid HS384 signature" in {

      createSignature(
        HsHeader(Hs384),
        Hs384Header,
        Payload
      ) shouldBe ValidSignatureHS384
    }

    "create valid HS512 signature" in {

      createSignature(
        HsHeader(Hs512),
        Hs512Header,
        Payload
      ) shouldBe ValidSignatureHS512
    }
  }

  "verifySignature" should {

    "accept and return with the verified signature for HS256" in {

      verifySignature(
        HsHeader(Hs256),
        Hs256Header,
        Payload,
        ValidSignatureHS256
      ) shouldBe Xor.Right(ValidSignatureHS256)
    }

    "accept and return with the verified signature for HS384" in {

      verifySignature(
        HsHeader(Hs384),
        Hs384Header,
        Payload,
        ValidSignatureHS384
      ) shouldBe Xor.Right(ValidSignatureHS384)
    }

    "accept and return with the verified signature for HS512" in {

      verifySignature(
        HsHeader(Hs512),
        Hs512Header,
        Payload,
        ValidSignatureHS512
      ) shouldBe Xor.Right(ValidSignatureHS512)
    }

    "reject invalid signature" in {

      verifySignature(
        HsHeader(Hs256),
        Hs256Header,
        Payload,
        InvalidSignatureHS256
      ) shouldBe Xor.Left(error.InvalidSignature)
    }

    "reject invalid short signature" in {

      verifySignature(
        HsHeader(Hs256),
        Hs256Header,
        Payload,
        InvalidShortSignatureHS256
      ) shouldBe Xor.Left(error.InvalidSignature)
    }
  }

  implicit val clock = DummyClock.fixedClock
  implicit val signerSettings = DummySettings.signerSettings
  implicit val verifierSettings = DummySettings.verifierSettings

  val Hs256Header = asBase64("""{"alg":"HS256","typ":"JWT"}""")
  val Hs384Header = asBase64("""{"alg":"HS384","typ":"JWT"}""")
  val Hs512Header = asBase64("""{"alg":"HS512","typ":"JWT"}""")

  val Payload = asBase64("""{"sub":"subject"}""")

  val ValidSignatureHS256 = "IzOEkLAHxQpn5ksibrxzITy_5dJFY7Op2mrfCNOrUcw"
  val ValidSignatureHS384 = "rEoTI6HSPMfbVLZtC3PD_h3lU4FRiNCxfQVf0gB7Cr_mZdWclpptQR3zikoJAL2A"
  val ValidSignatureHS512 = "WvikGjdf76l4wOrtuUfHmLi_h6atykfwnmUFrUQRDZ5YJwdDgMXoqiSTQim9XHI6xCVhaGkrPlRAFwkoUJOWUQ"

  val InvalidSignatureHS256 = "IzOEkLAHxQpn5ksibrxzITy_5dJFY7Op2mrfCNOrUcv"
  val InvalidShortSignatureHS256 = "invalid-and-short"
}
