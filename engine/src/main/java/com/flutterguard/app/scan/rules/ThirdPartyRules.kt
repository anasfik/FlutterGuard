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
            pubPackages = listOf("firebase_core", "firebase_analytics", "firebase_auth", "firebase_messaging", "cloud_firestore", "firebase_ai", "firebase_vertexai", "firebase_crashlytics", "firebase_remote_config"),
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
        Service("Datadog", dexPrefixes = listOf("com/datadog"), pubPackages = listOf("datadog_flutter_plugin", "datadog_flutter_plugin_flutterflow"), hosts = listOf("datadoghq.com"), note = "RUM/monitoring"),
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
        // ---- AI providers -------------------------------------------------
        // Split per provider on purpose: "some LLM" is not actionable. Which
        // provider and which key format decide the blast radius of a leak.
        Service("OpenAI", pubPackages = listOf("openai_dart", "dart_openai", "langchain_openai", "openai"),
            hosts = listOf("api.openai.com", "openai.azure.com"), note = "AI model calls"),
        Service("Anthropic", pubPackages = listOf("langchain_anthropic", "anthropic_sdk_dart", "anthropic"),
            hosts = listOf("api.anthropic.com"), note = "AI model calls"),
        Service("Google Gemini", pubPackages = listOf("google_generative_ai", "flutter_gemini", "langchain_google", "firebase_ai"),
            hosts = listOf("generativelanguage.googleapis.com", "aiplatform.googleapis.com", "firebasevertexai.googleapis.com"),
            note = "AI model calls"),
        Service("OpenRouter", pubPackages = listOf("openrouter_dart"), hosts = listOf("openrouter.ai"),
            note = "AI model aggregator; one key spends against many providers"),
        Service("DeepSeek", hosts = listOf("api.deepseek.com"), note = "AI model calls"),
        Service("Groq", hosts = listOf("api.groq.com"), note = "AI inference"),
        Service("Mistral", hosts = listOf("api.mistral.ai"), note = "AI model calls"),
        Service("Cohere", hosts = listOf("api.cohere.ai", "api.cohere.com"), note = "AI model calls"),
        Service("Together AI", hosts = listOf("api.together.xyz"), note = "AI inference"),
        Service("Fireworks AI", hosts = listOf("api.fireworks.ai"), note = "AI inference"),
        Service("Perplexity", hosts = listOf("api.perplexity.ai"), note = "AI model calls"),
        Service("xAI", hosts = listOf("api.x.ai"), note = "AI model calls"),
        Service("HuggingFace", pubPackages = listOf("huggingface_client", "flutter_huggingface"),
            hosts = listOf("huggingface.co", "router.huggingface.co", "hf.co"), note = "Model hub/inference"),
        Service("Replicate", hosts = listOf("api.replicate.com"), note = "Hosted model inference"),
        Service("AWS Bedrock", hosts = listOf("bedrock-runtime"), note = "AI model calls via AWS"),
        Service("Alibaba Qwen/DashScope", hosts = listOf("dashscope.aliyuncs.com"), note = "AI model calls"),
        Service("Moonshot", hosts = listOf("api.moonshot.cn"), note = "AI model calls"),
        Service("Zhipu GLM", hosts = listOf("open.bigmodel.cn"), note = "AI model calls"),
        Service("MiniMax", hosts = listOf("api.minimax.chat", "api.minimaxi.com"), note = "AI model calls"),
        Service("ElevenLabs", pubPackages = listOf("elevenlabs"), hosts = listOf("api.elevenlabs.io"), note = "Voice synthesis"),
        Service("Stability AI", hosts = listOf("api.stability.ai"), note = "Image generation"),
        Service("Ollama / LM Studio", pubPackages = listOf("ollama_dart", "flutter_llama"),
            hosts = listOf("localhost:11434", "localhost:1234"), note = "Local inference endpoint referenced in the build"),
        Service("ComfyUI / Stable Diffusion server", hosts = listOf(":8188"), note = "Local image-generation server referenced in the build"),
        Service("LangChain", pubPackages = listOf("langchain", "langchain_core"), note = "LLM orchestration; implies provider keys"),
        Service("MediaPipe GenAI", dexPrefixes = listOf("com/google/mediapipe/tasks/genai"), note = "On-device LLM"),
        Service("LiteRT", dexPrefixes = listOf("com/google/ai/edge/litert", "org/tensorflow/lite"),
            pubPackages = listOf("tflite_flutter"), note = "On-device model runtime"),
        Service("Cloudflare", hosts = listOf("cloudflare.com", "workers.dev", "r2.cloudflarestorage.com"), note = "Edge/storage"),
        Service("Resend/SendGrid", pubPackages = listOf("resend_dart"), hosts = listOf("resend.com", "sendgrid.net", "mailgun.org"), note = "Transactional email"),
        Service("Health/Consent", pubPackages = listOf("health", "flutter_health_connect"), note = "Health data access"),

        // ---- advertising ---------------------------------------------------
        // Ad SDKs are the second-largest data-exfiltration surface after
        // analytics: they ship their own device IDs, persistence and consent.
        Service("Google AdMob", dexPrefixes = listOf("com/google/android/gms/ads"),
            pubPackages = listOf("google_mobile_ads", "admob_flutter"),
            hosts = listOf("googleads.g.doubleclick.net", "pagead2.googlesyndication.com", "app-measurement.com"),
            note = "Advertising; collects advertising ID"),
        Service("Google UMP Consent", dexPrefixes = listOf("com/google/android/ump"), note = "GDPR consent for ads"),
        Service("AppLovin", dexPrefixes = listOf("com/applovin"), hosts = listOf("applovin.com", "ms.applovin.com"), note = "Mediation/ad network"),
        Service("Unity Ads", dexPrefixes = listOf("com/unity3d/ads", "com/unity3d/services"), hosts = listOf("unityads.unity3d.com"), note = "Ad network"),
        Service("IronSource", dexPrefixes = listOf("com/ironsource"), hosts = listOf("ironsrc.com", "supersonicads.com"), note = "Mediation/ad network"),
        Service("Mintegral", dexPrefixes = listOf("com/mintegral"), hosts = listOf("mintegral.com"), note = "Ad network"),
        Service("Pangle/CSJ", dexPrefixes = listOf("com/bytedance/sdk/openadsdk"), hosts = listOf("pangleglobal.com", "pangle.io"), note = "Ad network"),
        Service("Chartboost", dexPrefixes = listOf("com/chartboost"), hosts = listOf("chartboost.com"), note = "Ad network"),
        Service("InMobi", dexPrefixes = listOf("com/inmobi"), hosts = listOf("inmobi.com"), note = "Ad network"),
        Service("Vungle/Liftoff", dexPrefixes = listOf("com/vungle"), hosts = listOf("vungle.com", "liftoff.io"), note = "Ad network"),
        Service("AdColony", dexPrefixes = listOf("com/adcolony"), note = "Ad network"),
        Service("Amazon Publisher Services", dexPrefixes = listOf("com/amazon/device/ads"), note = "Ad network"),
        Service("Meta Audience Network", dexPrefixes = listOf("com/facebook/ads"), note = "Ad network"),
        Service("Digital Turbine/Fyber", dexPrefixes = listOf("com/fyber", "com/digitalturbine"), note = "Ad network"),
        Service("Smaato", dexPrefixes = listOf("com/smaato"), note = "Ad network"),
        Service("Sizmek/SQM", dexPrefixes = listOf("com/sqm"), note = "Ad network"),

        // ---- engagement / marketing ---------------------------------------
        Service("CleverTap", dexPrefixes = listOf("com/clevertap"), hosts = listOf("clevertap.com"), note = "Engagement/analytics"),
        Service("MoEngage", dexPrefixes = listOf("com/moengage"), hosts = listOf("moengage.com"), note = "Engagement/analytics"),
        Service("Airship", dexPrefixes = listOf("com/urbanairship", "com/airship"), hosts = listOf("urbanairship.com", "airship.com"), note = "Push/engagement"),
        Service("Iterable", dexPrefixes = listOf("io/iterable"), hosts = listOf("iterable.com"), note = "Marketing messaging"),
        Service("Klaviyo", dexPrefixes = listOf("com/klaviyo"), hosts = listOf("klaviyo.com"), note = "Marketing"),
        Service("Customer.io", hosts = listOf("customer.io"), note = "Marketing messaging"),
        Service("Singular", dexPrefixes = listOf("com/singular/sdk"), hosts = listOf("singular.net"), note = "Attribution"),
        Service("Kochava", dexPrefixes = listOf("com/kochava"), hosts = listOf("kochava.com"), note = "Attribution"),
        Service("Facebook App Events", pubPackages = listOf("facebook_app_events"), note = "Ad events"),

        // ---- identity ------------------------------------------------------
        Service("Auth0", dexPrefixes = listOf("com/auth0"), pubPackages = listOf("auth0"),
            hosts = listOf("auth0.com"), note = "Identity provider"),
        Service("Clerk", dexPrefixes = listOf("com/clerk"), pubPackages = listOf("clerk_flutter"),
            hosts = listOf("clerk.com", "clerk.dev"), note = "Identity provider"),
        Service("Appwrite", dexPrefixes = listOf("io/appwrite"), pubPackages = listOf("appwrite"),
            hosts = listOf("appwrite.io", "cloud.appwrite.io"), note = "Backend + auth"),
        Service("Stytch", dexPrefixes = listOf("com/stytch"), hosts = listOf("stytch.com"), note = "Identity provider"),
        Service("WorkOS", dexPrefixes = listOf("com/workos"), hosts = listOf("workos.com"), note = "Enterprise SSO"),
        Service("Okta", dexPrefixes = listOf("com/okta")), 
        Service("Keycloak", pubPackages = listOf("keycloak_flutter", "openid_client"), note = "Self-hosted identity"),
        Service("Firebase Auth", pubPackages = listOf("firebase_auth", "firebase_auth_web"), note = "Identity (Firebase)"),

        // ---- realtime / communications -------------------------------------
        Service("Agora", dexPrefixes = listOf("io/agora"), pubPackages = listOf("agora_rtc_engine", "agora_uikit"),
            hosts = listOf("agora.io", "sd-rtn.com"), note = "Voice/video RTC"),
        Service("LiveKit", dexPrefixes = listOf("io/livekit"), pubPackages = listOf("livekit_client"),
            hosts = listOf("livekit.io", "livekit.cloud"), note = "Voice/video RTC"),
        Service("Sendbird", dexPrefixes = listOf("com/sendbird"), pubPackages = listOf("sendbird_sdk"),
            hosts = listOf("sendbird.com"), note = "Chat"),
        Service("Stream Chat", dexPrefixes = listOf("io/getstream"), pubPackages = listOf("stream_chat_flutter"),
            hosts = listOf("getstream.io"), note = "Chat/feeds"),
        Service("Jitsi", dexPrefixes = listOf("org/jitsi"), pubPackages = listOf("jitsi_meet_flutter_sdk"),
            hosts = listOf("jitsi.org", "8x8.vc"), note = "Video conferencing"),
        Service("Daily", hosts = listOf("daily.co"), note = "Voice/video RTC"),
        Service("Vonage/Nexmo", pubPackages = listOf("vonage_voice"), hosts = listOf("vonage.com", "nexmo.com"), note = "Voice/SMS"),
        Service("MQTT broker", pubPackages = listOf("mqtt_client"), note = "IoT messaging"),
        Service("WebSocket", pubPackages = listOf("web_socket_channel"), note = "Realtime socket transport"),

        // ---- payments ------------------------------------------------------
        Service("PayPal", dexPrefixes = listOf("com/paypal"), pubPackages = listOf("flutter_paypal", "paypal_sdk"),
            hosts = listOf("paypal.com", "paypalobjects.com"), note = "Payments"),
        Service("Braintree", dexPrefixes = listOf("com/braintree"), hosts = listOf("braintreegateway.com", "braintree-api.com"), note = "Payments"),
        Service("Paddle", dexPrefixes = listOf("com/paddle"), pubPackages = listOf("paddle_flutter"),
            hosts = listOf("paddle.com"), note = "Payments/subscriptions"),
        Service("LemonSqueezy", hosts = listOf("lemonsqueezy.com"), note = "Payments"),
        Service("Razorpay", dexPrefixes = listOf("com/razorpay"), pubPackages = listOf("razorpay_flutter"),
            hosts = listOf("razorpay.com"), note = "Payments"),
        Service("Adyen", dexPrefixes = listOf("com/adyen"), hosts = listOf("adyen.com"), note = "Payments"),
        Service("Google Play Integrity", dexPrefixes = listOf("com/google/android/play/core/integrity"),
            note = "Device attestation"),

        // ---- backends ------------------------------------------------------
        Service("PocketBase", pubPackages = listOf("pocketbase", "pocketbase_dart"), note = "Self-hosted backend"),
        Service("Nhost", pubPackages = listOf("nhost_flutter_auth", "nhost_flutter_graphql"), hosts = listOf("nhost.io", "graphql.eu"), note = "Backend as a service"),
        Service("Parse", pubPackages = listOf("parse_server_sdk_flutter", "parse_server_sdk"), note = "Backend as a service"),
        Service("GraphQL", pubPackages = listOf("graphql_flutter", "gql"), note = "GraphQL client"),
        Service("gRPC", pubPackages = listOf("grpc"), dexPrefixes = listOf("io/grpc"), note = "RPC transport"),
        Service("Vercel", hosts = listOf("vercel.app", "vercel.com"), note = "Hosting"),
        Service("Railway", hosts = listOf("railway.app"), note = "Hosting"),
        Service("Render", hosts = listOf("onrender.com"), note = "Hosting"),
        Service("Fly.io", hosts = listOf("fly.dev"), note = "Hosting"),
        Service("Heroku", hosts = listOf("herokuapp.com"), note = "Hosting"),
        Service("DigitalOcean", hosts = listOf("digitaloceanspaces.com", "ondigitalocean.app"), note = "Hosting/storage"),
        Service("Backblaze B2", hosts = listOf("backblazeb2.com"), note = "Object storage"),

        // ---- search / vector ----------------------------------------------
        Service("Pinecone", hosts = listOf("pinecone.io", "svc.pinecone.io"), note = "Vector search"),
        Service("Qdrant", hosts = listOf("qdrant.io", "cloud.qdrant.io"), note = "Vector search"),
        Service("Weaviate", hosts = listOf("weaviate.io", "weaviate.cloud"), note = "Vector search"),
        Service("Typesense", hosts = listOf("typesense.net"), pubPackages = listOf("typesense"), note = "Search"),
        Service("Meilisearch", hosts = listOf("meilisearch.com"), note = "Search"),
        Service("Elastic", hosts = listOf("elastic-cloud.com", "es.io"), note = "Search"),
        Service("Algolia (hosts)", hosts = listOf("algolia.io"), note = "Search"),

        // ---- on-device servers ----------------------------------------------
        // A bundled HTTP server in a mobile app is an attack surface the
        // manifest never shows; shelf/dart_frog make it a one-liner.
        Service("On-device HTTP server", pubPackages = listOf("shelf", "shelf_router", "dart_frog", "dhttpd", "angel3_framework"),
            note = "Bundled Dart HTTP server — reachable on the local network if bound to 0.0.0.0"),

        // ---- local storage / crypto -----------------------------------------
        Service("SQLCipher", dexPrefixes = listOf("net/sqlcipher"), pubPackages = listOf("sqflite_sqlcipher", "sqlcipher_flutter_libs"), note = "Encrypted database"),
        Service("Realm", dexPrefixes = listOf("io/realm"), pubPackages = listOf("realm"), note = "Local database"),
        Service("Hive/Isar", pubPackages = listOf("hive", "hive_flutter", "isar"), note = "Local database (unencrypted by default)"),
        Service("flutter_secure_storage", pubPackages = listOf("flutter_secure_storage"), note = "Keystore-backed secrets"),
        Service("Biometric auth", dexPrefixes = listOf("androidx/biometric"), pubPackages = listOf("local_auth"), note = "Device biometrics"),
        Service("Android WorkManager", dexPrefixes = listOf("androidx/work"), note = "Background scheduling"),
        Service("ExoPlayer/Media3", dexPrefixes = listOf("androidx/media3", "com/google/android/exoplayer2"), note = "Media playback"),
        Service("InAppWebView", dexPrefixes = listOf("com/pichillilorenzo/flutter_inappwebview"),
            pubPackages = listOf("flutter_inappwebview", "webview_flutter"), note = "Embedded browser surface"),
        Service("Camera/ML Kit", dexPrefixes = listOf("com/google/mlkit"), pubPackages = listOf("google_mlkit_text_recognition", "camera"), note = "Camera/on-device ML"),
        Service("Share/receive", pubPackages = listOf("receive_sharing_intent", "share_plus", "share_handler"), note = "Inbound data from other apps"),
        Service("URL launcher", pubPackages = listOf("url_launcher"), note = "Outbound intent surface"),
        // ---- modern Flutter runtime surface ----
        // Reached by studying the top-downloaded Flutter packages: these are the
        // ones that carry a real security story but that no vendor fingerprint
        // covered. Generic plumbing (dio, http, riverpod, go_router) is left out
        // on purpose - it names no third party.
        Service(
            "Genkit (Dart AI agents)",
            pubPackages = listOf("genkit", "genkit_google_genai", "genkit_anthropic", "genkit_openai", "genkit_middleware"),
            note = "Agentic AI orchestration; prompt templates and tool definitions ship inside the app",
        ),
        Service(
            "Dart FFI / JNI bridge",
            pubPackages = listOf("jni", "jni_flutter", "objective_c", "jnigen"),
            dexPrefixes = listOf("com/github/dart_lang/jni"),
            note = "Native code called from Dart; memory-safety and ABI bugs are reachable from here",
        ),
        Service(
            "Multicast DNS / LAN discovery",
            pubPackages = listOf("multicast_dns", "nsd", "bonsoir", "flutter_nsd"),
            note = "Finds devices on the local network; exposes peer identity and service names",
        ),
        Service(
            "Crypto primitives (PointyCastle)",
            pubPackages = listOf("pointycastle", "cryptography", "cryptography_flutter", "encrypt"),
            note = "Cryptography implemented in Dart; check mode, padding and key handling",
        ),
        Service(
            "Location services",
            pubPackages = listOf("geolocator", "location", "flutter_background_geolocation"),
            hosts = listOf("maps.googleapis.com"),
            note = "Precise location access",
        ),
        Service(
            "Local notifications",
            pubPackages = listOf("flutter_local_notifications", "awesome_notifications"),
            dexPrefixes = listOf("com/dexterous/flutterlocalnotifications"),
            note = "Notification surface, including full-screen and action intents",
        ),
        Service(
            "Device capture and playback",
            pubPackages = listOf("image_picker", "file_picker", "video_player", "just_audio", "record", "camera"),
            note = "Reads user files, camera and microphone",
        ),
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
