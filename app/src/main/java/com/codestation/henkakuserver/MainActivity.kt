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

import android.Manifest
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Bundle
import android.support.annotation.RequiresPermission
import android.support.design.widget.Snackbar
import android.support.v4.content.ContextCompat
import android.support.v7.app.AppCompatActivity
import android.view.KeyEvent
import android.view.View
import kotlinx.android.synthetic.main.activity_main.*

import java.io.IOException


class MainActivity : AppCompatActivity() {

    // INSTANCE OF ANDROID WEB SERVER
    private var henkakuServer: HenkakuServer = HenkakuServer(this, BuildConfig.defaultPort)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        versionText.text = BuildConfig.VERSION_NAME

        textViewIpAccess.text = getString(R.string.enable_access_point)

        floatingActionButtonOnOff.setOnClickListener {
            updateServerStatus()
        }

        // INIT BROADCAST RECEIVER TO LISTEN NETWORK STATE CHANGED
        initBroadcastReceiverNetworkStateChanged()
    }

    private fun updateServerStatus() {
        if (isApOnline()) {
            if (!isStarted && startAndroidWebServer()) {
                isStarted = true
                textViewIpAccess.text = getString(R.string.default_host, BuildConfig.defaultAddress, BuildConfig.defaultPort)
                textViewMessage.visibility = View.VISIBLE
                floatingActionButtonOnOff.backgroundTintList = ContextCompat.getColorStateList(this@MainActivity, R.color.colorGreen)
            } else if (stopAndroidWebServer()) {
                isStarted = false
                textViewMessage.visibility = View.INVISIBLE
                textViewIpAccess.text = getString(R.string.enable_access_point)
                floatingActionButtonOnOff.backgroundTintList = ContextCompat.getColorStateList(this@MainActivity, R.color.colorRed)
            }
        } else {
            Snackbar.make(coordinatorLayout, getString(R.string.wifi_message), Snackbar.LENGTH_LONG).show()
        }
    }

    //region Start And Stop AndroidWebServer
    private fun startAndroidWebServer(): Boolean {
        if (!isStarted) {
            try {
                henkakuServer.start()
                return true
            } catch (e: IOException) {
                e.printStackTrace()
                Snackbar.make(coordinatorLayout, "Cannot start HenkakuServer listening on port ${BuildConfig.defaultPort}", Snackbar.LENGTH_LONG).show()
            }

        }
        return false
    }

    private fun stopAndroidWebServer(): Boolean {
        if (isStarted) {
            henkakuServer.stop()
            return true
        }
        return false
    }
    //endregion

    private fun initBroadcastReceiverNetworkStateChanged() {
        val filters = IntentFilter()
        filters.addAction("android.net.wifi.WIFI_STATE_CHANGED")
        filters.addAction("android.net.wifi.STATE_CHANGE")
        filters.addAction("android.net.wifi.WIFI_AP_STATE_CHANGED")

        val broadcastReceiverNetworkState = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                updateServerStatus()
            }
        }
        super.registerReceiver(broadcastReceiverNetworkState, filters)
    }

    @RequiresPermission(value = Manifest.permission.ACCESS_NETWORK_STATE)
    private fun isApOnline(): Boolean {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val method = wifiManager.javaClass.getDeclaredMethod("isWifiApEnabled")
        method.isAccessible = true
        return method.invoke(wifiManager) as Boolean
    }
    //endregion

    override fun onKeyDown(keyCode: Int, evt: KeyEvent): Boolean {
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (isStarted) {
                AlertDialog.Builder(this)
                        .setTitle(R.string.warning)
                        .setMessage(R.string.dialog_exit_message)
                        .setPositiveButton(resources.getString(android.R.string.ok)) { _, _ -> finish() }
                        .setNegativeButton(resources.getString(android.R.string.cancel), null)
                        .show()
            } else {
                finish()
            }
            return true
        }
        return false
    }

    override fun onDestroy() {
        super.onDestroy()
        stopAndroidWebServer()
        isStarted = false
    }

    companion object {
        private var isStarted = false
    }

}
