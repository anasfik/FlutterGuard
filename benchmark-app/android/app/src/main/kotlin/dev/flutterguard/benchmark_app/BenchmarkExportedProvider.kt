package dev.flutterguard.benchmark_app

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * Planted exported component: a content provider other apps can query,
 * declared with grantUriPermissions so a caller can pass read access on.
 * It exposes no data; the planted fact is the reachable surface.
 */
class BenchmarkExportedProvider : ContentProvider() {
    override fun onCreate(): Boolean = true
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
