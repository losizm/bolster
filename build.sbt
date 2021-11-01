organization := "com.github.losizm"
name         := "ergo"
version      := "1.1.0"
description  := "For contextual security in Scala"
homepage     := Some(url("https://github.com/losizm/ergo"))
licenses     := List("Apache License, Version 2" -> url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

scalaVersion := "3.1.0"

scalacOptions := Seq("-deprecation", "-feature", "-new-syntax", "-Yno-experimental")

Compile / doc / scalacOptions := Seq(
  "-project", name.value.capitalize,
  "-project-version", version.value,
  "-project-logo", "images/logo.svg"
)

libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.9" % "test"

developers := List(
  Developer(
    id    = "losizm",
    name  = "Carlos Conyers",
    email = "carlos.conyers@hotmail.com",
    url   = url("https://github.com/losizm")
  )
)

scmInfo := Some(
  ScmInfo(
    url("https://github.com/losizm/ergo"),
    "scm:git@github.com:losizm/ergo.git"
  )
)

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org"
  isSnapshot.value match {
    case true  => Some("snaphsots" at s"$nexus/content/repositories/snapshots")
    case false => Some("releases"  at s"$nexus/service/local/staging/deploy/maven2")
  }
}

pomIncludeRepository := (_ => false)
