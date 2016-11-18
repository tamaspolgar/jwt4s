package com.menzus.jwt4s

import java.time.Clock
import java.time.Instant
import java.time.ZoneId

object DummyClock {
  val fixedClock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
}
