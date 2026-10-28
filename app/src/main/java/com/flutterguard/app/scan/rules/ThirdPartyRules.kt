package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.ThirdPartyHit

/**
 * Third-party service detection across four evidence classes:
 * bundled files, DEX class descriptors, Dart pub packages (package: URIs in
 * libapp.so), and network hosts.
 */
object ThirdPartyRules {

    data class Service(
        val name: String,
        val files: List<String> = emptyList(),      // zip path fragments
        val dexPrefixes: List<String> = emptyList(),// Lcom/… descriptor fragments
        val pubPackages: List<String> = emptyList(),
        val hosts: List<String> = emptyList(),
        val note: String = "",
    )

    val services = listOf(
        Service("Firebase", files = listOf("google-services.json", "firebase_options"),
            dexPrefixes = listOf("com/google/firebase", "io/flutter/plugins/firebase"),
            pubPackages = listOf("firebase_core", "firebase_analytics", "firebase_auth", "firebase_messaging", "cloud_firestore"),
            hosts = listOf("firebaseio.com", "crashlytics.com", "app-measurement.com", "firebaseinstallations.googleapis.com"),
            note = "Google analytics/auth/messaging/crash reporting"),
        Service("Google Play Services", dexPrefixes = listOf("com/google/android/gms"), hosts = listOf("googleapis.com"),
            note = "Maps/Sign-in/ads identifier availability"),
        Service("Google Billing", dexPrefixes = listOf("com/android/billingclient"), pubPackages = listOf("in_app_purchase"), note = "In-app purchases"),
        Service("Sentry", dexPrefixes = listOf("io/sentry"), pubPackages = listOf("sentry", "sentry_flutter"), hosts = listOf("sentry.io"), note = "Crash/error reporting"),
        Service("Stripe", dexPrefixes = listOf("com/stripe"), pubPackages = listOf("stripe_flutter", "flutter_stripe"), hosts = listOf("stripe.com"), note = "Payments"),
        Service("RevenueCat", dexPrefixes = listOf("com/revenuecat"), pubPackages = listOf("purchases_flutter"), hosts = listOf("revenuecat.com"), note = "Subscription management"),
        Service("OneSignal", dexPrefixes = listOf("com/onesignal"), pubPackages = listOf("onesignal_flutter"), hosts = listOf("onesignal.com"), note = "Push notifications"),
        Service("Supabase", dexPrefixes = listOf("io/supabase"), pubPackages = listOf("supabase_flutter", "supabase"), hosts = listOf("supabase.co"), note = "Backend/database"),
        Service("AWS Mobile", dexPrefixes = listOf("com/amazonaws", "com/amplifyframework"), hosts = listOf("amazonaws.com", "cloudfront.net"), note = "Cloud backend"),
        Service("AppsFlyer", dexPrefixes = listOf("com/appsflyer"), pubPackages = listOf("appsflyer_sdk"), hosts = listOf("appsflyer.com"), note = "Attribution/tracking"),
        Service("Adjust", dexPrefixes = listOf("com/adjust"), pubPackages = listOf("adjust_sdk"), hosts = listOf("adjust.com"), note = "Attribution/tracking"),
        Service("Branch", dexPrefixes = listOf("io/branch"), pubPackages = listOf("branch_sdk_flutter"), hosts = listOf("branch.io"), note = "Deep-link attribution"),
        Service("Braze", dexPrefixes = listOf("com/braze"), hosts = listOf("braze.com"), note = "Engagement/tracking"),
        Service("Mixpanel", dexPrefixes = listOf("com/mixpanel"), pubPackages = listOf("mixpanel_flutter"), hosts = listOf("mixpanel.com"), note = "Product analytics"),
        Service("Amplitude", dexPrefixes = listOf("com/amplitude"), hosts = listOf("amplitude.com"), note = "Product analytics"),
        Service("Segment", dexPrefixes = listOf("com/segment"), hosts = listOf("segment.io"), note = "CDP/analytics piping"),
        Service("Facebook SDK", dexPrefixes = listOf("com/facebook"), pubPackages = listOf("facebook_app_events", "flutter_facebook_auth"), hosts = listOf("facebook.com", "fbcdn.net"), note = "Auth/events/advertising ID"),
        Service("Bugsnag", dexPrefixes = listOf("com/bugsnag"), hosts = listOf("bugsnag.com"), note = "Crash reporting"),
        Service("Datadog", dexPrefixes = listOf("com/datadog"), hosts = listOf("datadoghq.com"), note = "RUM/monitoring"),
        Service("AppDynamics/NewRelic", dexPrefixes = listOf("com/newrelic"), hosts = listOf("nr-data.net"), note = "APM"),
        Service("PostHog", dexPrefixes = listOf("com/posthog"), pubPackages = listOf("posthog_flutter"), hosts = listOf("posthog.com"), note = "Product analytics"),
        Service("Mapbox", dexPrefixes = listOf("com/mapbox"), pubPackages = listOf("mapbox_gl", "mapbox_maps_flutter"), hosts = listOf("mapbox.com", "tiles.mapbox.com"), note = "Maps/tiles"),
        Service("Twilio", pubPackages = listOf("flutter_twilio_voice", "twilio_flutter"), hosts = listOf("twilio.com"), note = "Voice/SMS"),
        Service("Intercom", dexPrefixes = listOf("io/intercom"), pubPackages = listOf("intercom_flutter"), hosts = listOf("intercom.io", "intercomcdn.com"), note = "Support chat"),
        Service("Zendesk", dexPrefixes = listOf("com/zendesk"), pubPackages = listOf("zendesk_messaging"), hosts = listOf("zendesk.com"), note = "Support"),
        Service("Algolia", pubPackages = listOf("algolia", "algoliasearch"), hosts = listOf("algolia.net", "algolianet.com"), note = "Search"),
        Service("Pusher/Ably", pubPackages = listOf("pusher_channels_flutter", "ably_flutter"), hosts = listOf("pusher.com", "ably.io"), note = "Realtime messaging"),
        Service("LaunchDarkly", pubPackages = listOf("launchdarkly_flutter_client_sdk"), hosts = listOf("launchdarkly.com"), note = "Feature flags"),
        Service("Adapty", dexPrefixes = listOf("com/adapty"), pubPackages = listOf("adapty_flutter"), hosts = listOf("adapty.io"), note = "Paywall/subscriptions"),
        Service("OpenAI/LLM", pubPackages = listOf("openai_dart", "langchain", "google_generative_ai", "dart_openai"), hosts = listOf("openai.com", "anthropic.com", "generativelanguage.googleapis.com"), note = "AI model calls"),
        Service("Cloudflare", hosts = listOf("cloudflare.com", "workers.dev", "r2.cloudflarestorage.com"), note = "Edge/storage"),
        Service("Resend/SendGrid", pubPackages = listOf("resend_dart"), hosts = listOf("resend.com", "sendgrid.net", "mailgun.org"), note = "Transactional email"),
        Service("Health/Consent", pubPackages = listOf("health", "flutter_health_connect"), note = "Health data access"),
    )

    private val dexPrefixToService = services.flatMap { s -> s.dexPrefixes.map { it to s.name } }

    /** Cheap contains-check invoked per DEX string while streaming. */
    fun checkDexString(s: String, hits: MutableMap<String, MutableSet<String>>) {
        if (s.length > 250) return
        for ((prefix, name) in dexPrefixToService) {
            if (s.contains(prefix)) hits.getOrPut(name) { LinkedHashSet() }.add(prefix)
        }
    }

    fun detect(
        zipNames: Set<String>,
        dexPrefixHits: Map<String, Set<String>>,
        dartDeps: Set<String>,
        hosts: Map<String, String>,
    ): List<ThirdPartyHit> {
        val out = ArrayList<ThirdPartyHit>()
        for (s in services) {
            val ev = ArrayList<String>()
            for (f in s.files) if (zipNames.any { it.contains(f) }) ev.add("file:*$f*")
            dexPrefixHits[s.name]?.let { pfx -> if (pfx.isNotEmpty()) ev.add("dex:" + pfx.first()) }
            for (p in s.pubPackages) if (dartDeps.contains(p)) ev.add("pub:$p")
            for (h in s.hosts) if (hosts.keys.any { it == h || it.endsWith(".$h") }) ev.add("host:$h")
            if (ev.isNotEmpty()) out.add(ThirdPartyHit(s.name, ev))
        }
        return out
    }
}
