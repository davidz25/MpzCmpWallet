package org.multipaz.samples.wallet.cmp

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import mpzcmpwallet.composeapp.generated.resources.Res
import mpzcmpwallet.composeapp.generated.resources.compose_multiplatform
import org.jetbrains.compose.resources.painterResource
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Simple
import org.multipaz.compose.permissions.rememberBluetoothPermissionState
import org.multipaz.compose.presentment.Presentment
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.compose.qrcode.generateQrCode
import org.multipaz.compose.qrcode.QrCodeDisplay
import org.multipaz.compose.qrcode.startQrPresentment
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.engagement.EngagementGenerator
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.transport.MdocTransportFactory
import org.multipaz.mdoc.transport.MdocTransportOptions
import org.multipaz.mdoc.transport.advertise
import org.multipaz.mdoc.transport.waitForConnection
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.models.presentment.MdocPresentmentMechanism
import org.multipaz.models.presentment.PresentmentModel
import org.multipaz.models.presentment.SimplePresentmentSource
import org.multipaz.prompt.PromptModel
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustPoint
import org.multipaz.util.Platform
import org.multipaz.util.UUID
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.days

// NOTE: This is currently using code from the framework-export branch
//
// Remaining work:
//  - Simplify DocumentMetadata
//  - Get rid of CredentialLoader but allow a way to register additional credential types on a DocumentStore
//

/**
 * Application singleton.
 *
 * Use [App.Companion.getInstance] to get an instance.
 */
class App(val promptModel: PromptModel) {

    lateinit var storage: Storage
    lateinit var documentTypeRepository: DocumentTypeRepository
    lateinit var secureAreaRepository: SecureAreaRepository
    lateinit var secureArea: SecureArea
    lateinit var documentStore: DocumentStore
    lateinit var readerTrustManager: TrustManager
    val presentmentModel = PresentmentModel().apply { setPromptModel(promptModel) }

    private val initLock = Mutex()
    private var initialized = false

    suspend fun init() {
        initLock.withLock {
            if (initialized) {
                return
            }
            storage = Platform.getNonBackedUpStorage()
            secureArea = Platform.getSecureArea(storage)
            secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build()
            documentTypeRepository = DocumentTypeRepository().apply {
                addDocumentType(DrivingLicense.getDocumentType())
            }
            documentStore = buildDocumentStore(storage = storage, secureAreaRepository = secureAreaRepository) {}

            createSampleDocument(documentStore, secureArea)
            readerTrustManager = createTestTrustManager()
        }
    }

    @Composable
    fun Content() {
        var isInitialized = remember { mutableStateOf<Boolean>(false) }
        if (!isInitialized.value) {
            CoroutineScope(Dispatchers.Main).launch {
                init()
                isInitialized.value = true
            }
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(text = "Initializing...")
            }
            return
        }

        MaterialTheme {
            val coroutineScope = rememberCoroutineScope { promptModel }
            val blePermissionState = rememberBluetoothPermissionState()

            PromptDialogs(promptModel)

            if (!blePermissionState.isGranted) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                blePermissionState.launchPermissionRequest()
                            }
                        }
                    ) {
                        Text("Request BLE permissions")
                    }
                }
            } else {
                PresentmentScreen()
            }
        }
    }

    @Composable
    private fun PresentmentScreen() {
        val deviceEngagement = remember { mutableStateOf<ByteString?>(null) }
        val state = presentmentModel.state.collectAsState()

        when (state.value) {
            PresentmentModel.State.IDLE -> showQrButton(deviceEngagement)
            PresentmentModel.State.CONNECTING -> showQrCode(deviceEngagement)
            else -> PresentmentContent()
        }
    }

    @Composable
    private fun showQrButton(deviceEngagement: MutableState<ByteString?>) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = {
                    startQrPresentment(presentmentModel, deviceEngagement)
                }
            ) {
                Text(text = "Present QR Code")
            }
        }
    }

    @Composable
    private fun showQrCode(deviceEngagement: MutableState<ByteString?>) {
        QrCodeDisplay(
            deviceEngagement = deviceEngagement,
            onCancel = { presentmentModel.reset() }
        )
    }

    @Composable
    fun PresentmentContent() = Presentment(
        presentmentModel = presentmentModel,
        promptModel = promptModel,
        documentTypeRepository = documentTypeRepository,
        source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypeRepository,
            readerTrustManager = readerTrustManager,
            preferSignatureToKeyAgreement = true,
            domainMdocSignature = "mdoc",
        ),
        onPresentmentComplete = { presentmentModel.reset() },
        appName = "MpzCmpWallet",
        appIconPainter = painterResource(Res.drawable.compose_multiplatform),
        modifier = Modifier
    )

    companion object {
        private var app: App? = null
        fun getInstance(promptModel: PromptModel): App {
            if (app == null) {
                app = App(promptModel)
            } else {
                check(app!!.promptModel === promptModel)
            }
            return app!!
        }
    }
}


