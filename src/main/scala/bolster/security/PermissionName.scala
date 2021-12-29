/*
 * Copyright 2021 Carlos Conyers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bolster.security

import scala.util.Try
import scala.util.matching.Regex

private class PermissionName(template: String): //
  private val regex = toRegex(template)

  inline def format(value: String): String =
    template.replace("{}", value.trim())

  inline def unapply(value: String): Option[String] =
    value match
      case regex(name) => Some(name)
      case _           => None

  private def toRegex(template: String): Regex =
    val index = template.indexOf("{}")

    StringBuilder()
      .append(Regex.quote(template.take(index)))
      .append("(.+?)")
      .append(Regex.quote(template.drop(index + 2)))
      .toString()
      .r

private object PermissionName:
  def user  = PermissionName(getTemplate("bolster.security.userPermissionTemplate", "<[[user=({})]]>"))
  def group = PermissionName(getTemplate("bolster.security.groupPermissionTemplate", "<[[group=({})]]>"))

  private def getTemplate(name: String, default: => String): String =
    Try(sys.props(name).trim()).filter(checkTemplate).getOrElse(default)

  private def checkTemplate(template: String): Boolean =
    template.contains("{}")
