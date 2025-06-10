package org.multipaz.samples.wallet.cmp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.coroutineScope
import kotlinx.coroutines.launch
import org.multipaz.context.initializeApplication
import org.multipaz.prompt.AndroidPromptModel

class MainActivity : FragmentActivity() {
    val promptModel = AndroidPromptModel()

    override fun onCreate(savedInstanceState: Bundle?) {
        initializeApplication(this.applicationContext)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        lifecycle.coroutineScope.launch {
            val app = App.getInstance(promptModel)
            app.init()
            setContent {
                app.Content()
            }
        }
    }
}
