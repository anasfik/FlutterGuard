package com.flutterguard.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.flutterguard.app.scan.InventoryStore
import com.flutterguard.app.scan.ReportFiles
import com.flutterguard.app.scan.ScanPhase
import com.flutterguard.app.scan.ScanStore
import com.flutterguard.app.scan.packageName
import com.flutterguard.app.ui.AppFilter
import com.flutterguard.app.ui.Destination
import com.flutterguard.app.ui.DetailsScreen
import com.flutterguard.app.ui.FlutterGuardTheme
import com.flutterguard.app.ui.HomeScreen
import com.flutterguard.app.ui.NavStack
import com.flutterguard.app.ui.PackageId
import com.flutterguard.app.ui.QueueRoute
import com.flutterguard.app.ui.ScanNotifier
import com.flutterguard.app.ui.ScanQueueRunner
import com.flutterguard.app.ui.SearchUi
import com.flutterguard.app.ui.SectionRoute
import com.flutterguard.app.ui.scanPhaseFeed

class MainActivity : ComponentActivity() {

    /** Kept observable so the UI can say "no notification" instead of promising one. */
    private var notificationsAllowed by mutableStateOf(true)

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            notificationsAllowed = granted && NotificationManagerCompat.from(this).areNotificationsEnabled()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Headless mode for scripted audits:
        //   adb shell am start -n com.flutterguard.app/.MainActivity -e scan com.example.app
        // The scan service owns execution, writes files/reports/<pkg>.json and logs "FG_REPORT <path>".
        if (handleScanIntent(intent)) {
            finish()
            return
        }
        notificationsAllowed = NotificationManagerCompat.from(this).areNotificationsEnabled()
        askForNotificationPermission()
        setContent {
            FlutterGuardTheme {
                AppNav(notificationsAllowed = notificationsAllowed)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // A scan request delivered while the activity is already foreground must start too;
        // otherwise scripted scans fail silently whenever the app is open.
        if (handleScanIntent(intent)) {
            finish()
        }
    }

    /** Returns true when the intent carries a headless scan request (handled or attempted). */
    private fun handleScanIntent(intent: Intent?): Boolean {
        val target = intent?.getStringExtra("scan")
        if (target.isNullOrBlank()) return false
        if (!ScanService.start(this, target, headless = true)) {
            android.util.Log.e("FlutterGuard", "FG_ERROR could not start scan service for $target")
        }
        return true
    }

    /** Android 13+: without the notification permission the scan still runs, but silently. */
    private fun askForNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}

/**
 * Navigation + state that must survive screen changes: the inventory, scan
 * state, search, filters and list scroll live here (process stores +
 * rememberSaveable), so Back and rotation neither reload the inventory nor
 * cancel a scan.
 *
 * There is one navigation source of truth: [NavStack]. Every screen — Home,
 * an app's Details, a See-all Section — is a destination pushed onto it, so
 * Back pops a route instead of unwinding a composable nested in another
 * screen. The scan lifecycle is untouched by navigation: it belongs to
 * `ScanService` + `ScanStore`, so leaving Details mid-scan neither stops nor
 * restarts anything.
 */
@Composable
private fun AppNav(notificationsAllowed: Boolean) {
    val context = LocalContext.current
    val inventory by InventoryStore.state.collectAsState()
    val scan by ScanStore.state.collectAsState()
    val queue by ScanQueueRunner.state.collectAsState()

    // Saved as plain strings (NavStack.save/restore): a rotation keeps the
    // route the user was on without a navigation dependency.
    var stack by rememberSaveable(
        stateSaver = listSaver(
            save = { NavStack.save(it) },
            restore = { NavStack.restore(it) },
        ),
    ) { mutableStateOf(NavStack.root()) }
    var search by rememberSaveable(
        stateSaver = listSaver(
            save = { listOf(it.expanded, it.query) },
            restore = { SearchUi(expanded = it[0] as Boolean, query = it[1] as String) },
        ),
    ) { mutableStateOf(SearchUi()) }
    var advanced by rememberSaveable { mutableStateOf(false) }
    var flutterOnly by rememberSaveable { mutableStateOf(true) }
    var hideSystem by rememberSaveable { mutableStateOf(true) }
    var packageInput by rememberSaveable { mutableStateOf("") }
    var packageError by remember { mutableStateOf<String?>(null) }
    val listState = rememberLazyListState()
    var interrupted by remember { mutableStateOf<List<String>>(emptyList()) }

    LaunchedEffect(Unit) {
        // A leftover marker means the process died mid-scan: say so, never call it a success.
        // A scan that is still running owns its marker, so only stale markers are reported and cleared.
        val dir = ReportFiles.appDir(context)
        val live = listOfNotNull(ScanStore.state.value.running?.job?.packageName)
        interrupted = ReportFiles.interrupted(dir, keep = live)
        ReportFiles.clearInterrupted(dir, keep = live)
        InventoryStore.refresh(context)
    }

    val current = NavStack.current(stack)
    // Back order: Section → Details → Home → exit, and on Home an open search
    // collapses before the app exits. One handler, so no screen can hold Back.
    val searchOnHome = current == Destination.Home && search.expanded
    BackHandler(enabled = NavStack.canPop(stack) || searchOnHome) {
        if (searchOnHome) search.back()?.let { search = it }
        else stack = NavStack.pop(stack)
    }    // B3: a scan that ends while the user is elsewhere posts one result
    // notification. The queue posts its own summary, and watching this package
    // in Details is already visible feedback.
    // A3: `scanPhaseFeed()` is the store's StateFlow, not snapshot state, so the
    // terminal emission is real. LaunchedEffect(Unit) keeps this one collector
    // for the activity's lifetime (recomposition does not recreate it).
    val viewing = rememberUpdatedState(
        when (current) {
            is Destination.Details -> current.packageName
            // A See-all list is still this app's data on screen.
            is Destination.Section -> current.packageName
            // The queue route watches the queue, not one app's terminal phase.
            Destination.Home, Destination.Queue -> null
        },
    )
    LaunchedEffect(Unit) {
        scanPhaseFeed().collect { phase ->
            val terminal = phase is ScanPhase.Done ||
                phase is ScanPhase.Failed ||
                phase is ScanPhase.Cancelled
            if (terminal && !ScanQueueRunner.state.value.active && phase.packageName != viewing.value) {
                ScanNotifier.terminal(context, phase)
            }
        }
    }

    // Each route keeps its own saved state while another route renders, so a tab
    // flip or Back from a See-all list returns to the same tab, filter and scroll
    // offset instead of resetting the screen. The key is route identity, not the
    // whole destination: switching tabs is still the same screen.
    val routeStates = rememberSaveableStateHolder()
    routeStates.SaveableStateProvider(NavStack.stateKey(current)) {
        when (current) {
            Destination.Home -> HomeScreen(
                state = inventory,
                phase = scan.phase,
                interrupted = interrupted,
                search = search,
                onSearch = { search = it },
                advanced = advanced,
                onAdvanced = { advanced = it },
                filter = AppFilter(query = search.query, flutterOnly = flutterOnly, hideSystem = hideSystem),
                onFilter = {
                    flutterOnly = it.flutterOnly
                    hideSystem = it.hideSystem
                },
                packageInput = packageInput,
                onPackageInput = {
                    packageInput = it
                    packageError = null
                },
                packageError = packageError,
                listState = listState,
                onRefresh = { InventoryStore.refresh(context, force = true) },
                // Navigating away closes the search UI (the query stays as the
                // filter), so returning to Home does not re-open a keyboard.
                onPick = { app ->
                    search = search.collapse()
                    stack = NavStack.push(stack, Destination.Details(app.packageName))
                },
                onOpenRunning = { pkg ->
                    search = search.collapse()
                    stack = NavStack.push(stack, Destination.Details(pkg))
                },
                onCancelScan = { ScanService.cancel(context) },
                onScanPackage = { pkg ->
                    if (!PackageId.isValid(pkg)) {
                        packageError = "Enter a dotted package id, e.g. com.example.app."
                    } else if (inventory.apps.none { it.packageName == pkg }) {
                        packageError = "Package not installed or not in the cached list. Refresh inventory and retry."
                    } else {
                        packageError = null
                        search = search.collapse()
                        stack = NavStack.push(stack, Destination.Details(pkg))
                    }
                },
                notificationsAllowed = notificationsAllowed,
                queue = queue,
                // Starting a queue and re-entering a running one are the same route.
                // Routing never starts or stops a scan; `start` is the explicit tap
                // on the confirmed dialog, and it already existed.
                onOpenQueue = {
                    search = search.collapse()
                    stack = NavStack.push(stack, Destination.Queue)
                },
                onScanAll = { apps ->
                    if (ScanQueueRunner.start(context, apps)) {
                        search = search.collapse()
                        stack = NavStack.push(stack, Destination.Queue)
                    } else {
                        Toast.makeText(
                            context,
                            "Scan-all not started: a scan is running or still stopping.",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                },
            )
            is Destination.Details -> DetailsScreen(
                app = inventory.apps.firstOrNull { it.packageName == current.packageName },
                packageName = current.packageName,
                phase = scan.phase,
                lastSuccess = scan.lastSuccess,
                section = current.section,
                // The tab belongs to the route: leaving for a See-all list and
                // coming back must land on the tab the user was reading.
                onSection = { name -> stack = NavStack.replaceTop(stack, current.copy(section = name)) },
                onBack = { stack = NavStack.pop(stack) },
                onSeeAll = { target, filter ->
                    stack = NavStack.push(stack, Destination.Section(current.packageName, target, filter))
                },
                onRescan = {
                    if (!ScanService.start(context, current.packageName)) {
                        Toast.makeText(context, "Scan not started: another scan is running or still stopping.", Toast.LENGTH_SHORT).show()
                    }
                },
                onCancel = { ScanService.cancel(context) },
            )
            is Destination.Section -> SectionRoute(
                destination = current,
                phase = scan.phase,
                lastSuccess = scan.lastSuccess,
                onBack = { stack = NavStack.pop(stack) },
            )
            // Queue rows push Details on top of this route, so Back from an app
            // opened here returns to the queue, never straight to Home.
            Destination.Queue -> QueueRoute(
                queue = queue,
                phase = scan.phase,
                notificationsAllowed = notificationsAllowed,
                onBack = { stack = NavStack.pop(stack) },
                onOpenApp = { pkg -> stack = NavStack.push(stack, Destination.Details(pkg)) },
                onCancelQueue = { ScanQueueRunner.cancelAll(context) },
                onDismiss = {
                    ScanQueueRunner.dismiss()
                    // A dismissed queue has nothing left to show here.
                    stack = NavStack.pop(stack)
                },
            )
        }
    }
}
