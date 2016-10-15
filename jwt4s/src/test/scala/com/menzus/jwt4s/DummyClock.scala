package com.menzus.jwt4s

object DummyClock {

  val fixedClock = new Clock {
    override def nowInMs(): Long = 0
  }
}
