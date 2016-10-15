package com.menzus.jwt4s

import org.scalatest.Matchers
import org.scalatest.WordSpec

class SystemClockSpec extends WordSpec with Matchers {

  "SystemClockSpec" should {

    "return current system time" in {

      val t0 = System.currentTimeMillis
      val t1 = Clock.system.nowInMs()
      val t2 = System.currentTimeMillis

      t1 should be >= t0
      t1 should be <= t2
    }
  }
}