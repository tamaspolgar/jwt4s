package com.menzus.jwt4s.internal

import cats.data.Xor
import com.menzus.jwt4s.error.InvalidStructure
import com.menzus.jwt4s.internal.RawParts.verifyAndExtractRawParts
import org.scalatest.Matchers
import org.scalatest.WordSpec

class RawPartsSpec extends WordSpec with Matchers {

  "Verifier" should {

    "return raw parts for valid token strucutre" in {

      verifyAndExtractRawParts("a.b.c") shouldBe Xor.Right(
        RawParts(headerBase64 = "a", payloadBase64 = "b", signatureBase64 = "c")
      )

      verifyAndExtractRawParts("ABCDEFGHIJKLMNOPQRSTUVWXYZ.abcdefghijklmnopqrstuvwxyz.0123456789-_") shouldBe
        Xor.Right(
          RawParts(
            headerBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            payloadBase64 = "abcdefghijklmnopqrstuvwxyz",
            signatureBase64 = "0123456789-_"
          )
        )
    }

    "reject token with non 3 parts" in {

      verifyAndExtractRawParts("") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts(".") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a.") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts(".a") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a.b") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("..") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a..") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts(".a.") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("..a") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a.b.") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts(".a.b") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("...") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a.b.c.") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts(".a.b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a.b.c.d") shouldBe Xor.Left(InvalidStructure)
    }

    "reject token with linebreak, whitespace and additional characters" in {

      verifyAndExtractRawParts("a\n.b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a\t.b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a .b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a@.b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a$.b.c") shouldBe Xor.Left(InvalidStructure)
      verifyAndExtractRawParts("a?.b.c") shouldBe Xor.Left(InvalidStructure)
    }
  }
}