package org.multipaz.samples.wallet.cmp

import androidx.compose.runtime.Composable
import org.multipaz.compose.mdoc.MdocNfcPresentmentActivity

class NfcActivity: MdocNfcPresentmentActivity() {
    @Composable
    override fun ApplicationTheme(content: @Composable (() -> Unit)) {
        content()
    }

    override suspend fun getSettings(): Settings {
        val app = App.getInstance()
        app.init()
        return Settings(
            appName = app.appName,
            appIcon = app.appIcon,
            promptModel = App.promptModel,
            documentTypeRepository = app.documentTypeRepository,
            presentmentSource = app.presentmentSource
        )
    }
}