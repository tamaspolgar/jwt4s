package com.menzus.jwt4s

trait Clock {
  def nowInMs(): Long

  final def nowInS(): Long = nowInMs / 1000
}

object Clock {
  val system = new Clock {
    def nowInMs(): Long = System.currentTimeMillis
  }
}