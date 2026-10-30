package com.flutterguard.app.scan

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.flutterguard.app.scan.parsers.AxmlDecoder
import java.io.File
import java.io.IOException
import java.io.InputStream

/** Raised when a picked or shared file cannot be turned into a scannable APK. */
class FileImportException(message: String) : Exception(message)

/**
 * The path that keeps FlutterGuard usable without broad package visibility: a
 * file picked with ACTION_OPEN_DOCUMENT or shared with ACTION_SEND is copied
 * into the app cache, its manifest is decoded for package identity, and the
 * normal scanner runs on the copied file.
 *
 * Android gives no durable read grant to a cache copy, so the copy is deleted by
 * the scan service once the job reaches a terminal state.
 */
object FileImport {

    /** A picked APK is a static artifact, but it is still data from outside the app: cap the copy. */
    const val MAX_BYTES = 512L * 1024 * 1024

    data class Imported(val file: File, val packageName: String, val label: String)

    /** Copies [uri] into the cache and identifies it. Throws [FileImportException] with a readable reason. */
    fun prepare(context: Context, uri: Uri): Imported {
        val dir = File(context.cacheDir, "imports").apply { mkdirs() }
        val display = displayName(context, uri)
        val safe = display.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(80)
            .ifBlank { "picked.apk" }
        val target = File(dir, "${System.currentTimeMillis()}_$safe")
        try {
            val stream = context.contentResolver.openInputStream(uri)
                ?: throw FileImportException("The picker returned no readable file.")
            stream.use { copyBounded(it, target, MAX_BYTES) }
        } catch (t: FileImportException) {
            runCatching { target.delete() }
            throw t
        } catch (t: IOException) {
            runCatching { target.delete() }
            throw FileImportException("Could not copy the file (${t.message ?: t::class.java.simpleName}).")
        }
        val meta = try {
            identify(target)
        } catch (t: Throwable) {
            runCatching { target.delete() }
            throw if (t is FileImportException) t else FileImportException(t.message ?: "Not a readable APK.")
        }
        return Imported(target, meta.packageName, meta.label)
    }

    /**
     * Package identity of a standalone APK. The manifest is the only authority:
     * there is no package-manager entry, so the name cannot be spoofed by the
     * file name (which is used only as the label fallback).
     */
    fun identify(apk: File): Scanner.FileMeta = ApkSource.forFile(apk).use { src ->
        val root = src.bytes("AndroidManifest.xml", maxBytes = 8 * 1024 * 1024)
            ?.let { AxmlDecoder.decode(it) }
            ?: throw FileImportException("No readable AndroidManifest.xml in this file; is it an APK?")
        Scanner.fileMeta(root, apk.nameWithoutExtension)
            ?: throw FileImportException("The manifest declares no package name; is it an APK?")
    }

    /** Bounded copy: refuses a file larger than [maxBytes] and never leaves a partial target behind. */
    fun copyBounded(input: InputStream, target: File, maxBytes: Long) {
        var total = 0L
        try {
            target.outputStream().use { out ->
                val buf = ByteArray(1 shl 16)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > maxBytes) throw FileImportException("The file is larger than ${maxBytes / 1024 / 1024} MB.")
                    out.write(buf, 0, n)
                }
            }
            if (total == 0L) throw FileImportException("The picked file is empty.")
        } catch (t: Throwable) {
            runCatching { target.delete() }
            throw t
        }
    }

    private fun displayName(context: Context, uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
        }.getOrNull()?.let { return it }
        return uri.lastPathSegment.orEmpty()
    }
}
