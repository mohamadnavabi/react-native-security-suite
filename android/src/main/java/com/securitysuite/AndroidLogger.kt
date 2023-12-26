package com.securitysuite

import android.util.Log
import com.moczul.ok2curl.logger.Logger

class AndroidLogger : Logger {

    override fun log(message: String) {
        curl = message

//        Log.v(TAG, message)
    }

    companion object {
        const val TAG = "Ok2Curl"

        @JvmStatic var curl : String? = null
    }
}