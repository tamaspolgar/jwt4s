package com.menzus.jwt4s.akkahttp

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory

class Settings private (val realm: String)

object Settings {

  def apply(): Settings = {
    apply(ConfigFactory.load)
  }

  def apply(config: Config): Settings = {
    new Settings(
      realm = config.getString("jwt.authenticator.realm")
    )
  }
}