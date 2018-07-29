/*
 * Copyright 2018 codestation. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codestation.henkakuserver

import android.content.Context

import java.io.FileNotFoundException
import java.io.IOException

import fi.iki.elonen.NanoHTTPD


internal class HenkakuServer(private val context: Context, port: Int) : NanoHTTPD(port) {

    override fun serve(session: NanoHTTPD.IHTTPSession): NanoHTTPD.Response {
        val response: NanoHTTPD.Response

        val uri = session.uri
        logd("Request URI: $uri")

        val agent = session.headers["user-agent"]
        if (agent != null && !agent.contains("PlayStation Vita 3.60") && (uri == "/" || uri == "stage1")) {
            logd("Request from non PS Vita, agent: $agent")
            return NanoHTTPD.newFixedLengthResponse("<html><body><h2>${context.getString(R.string.agent_message)}</h2></body></html>")
        }

        response = try {
            val isf = context.assets.open(uri.substring(1))
            val mime = NanoHTTPD.getMimeTypeForFile(uri)
            logd("Serving $uri with mime $mime")
            NanoHTTPD.newChunkedResponse(NanoHTTPD.Response.Status.OK, mime, isf)
        } catch (e: FileNotFoundException) {
            NanoHTTPD.newFixedLengthResponse(NanoHTTPD.Response.Status.NOT_FOUND, "text/plain", "Not found")
        } catch (e: IOException) {
            e.printStackTrace()
            NanoHTTPD.newFixedLengthResponse("<html><body><h3>Internal server error</h3></body></html>")
        }

        return response

    }

}
