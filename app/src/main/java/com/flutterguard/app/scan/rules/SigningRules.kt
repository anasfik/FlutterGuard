package com.flutterguard.app.scan.rules

import android.content.pm.PackageInfo
import android.os.Build
import com.flutterguard.app.scan.Finding
import com.flutterguard.app.scan.SigningInfo
import com.flutterguard.app.scan.Severity
import java.io.ByteArrayInputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Signing analysis: certificate identity + APK signature scheme presence. */
object SigningRules {

    fun evaluate(pi: PackageInfo, baseApkPath: String, zipNames: Set<String>): Pair<SigningInfo, List<Finding>> {
        val findings = ArrayList<Finding>()
        val notes = ArrayList<String>()

        val certBytes: List<ByteArray> = if (Build.VERSION.SDK_INT >= 28) {
            val si = pi.signingInfo
            when {
                si == null -> emptyList()
                si.hasMultipleSigners() -> si.apkContentsSigners?.map { it.toByteArray() } ?: emptyList()
                else -> si.signingCertificateHistory?.map { it.toByteArray() } ?: emptyList()
            }
        } else {
            @Suppress("DEPRECATION")
            pi.signatures?.map { it.toByteArray() } ?: emptyList()
        }

        val certs = certBytes.mapNotNull {
            runCatching {
                CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(it)) as X509Certificate
            }.getOrNull()
        }

        val first = certs.firstOrNull()
        val debugCert = first != null && first.subjectX500Principal.name.contains("CN=Android Debug", ignoreCase = true)
        val rotation = Build.VERSION.SDK_INT >= 28 && pi.signingInfo?.hasPastSigningCertificates() == true
        val schemes = detectSchemes(baseApkPath, zipNames)

        if (debugCert) findings += Finding(
            id = "SIG-DEBUG",
            title = "Signed with a debug certificate",
            severity = Severity.HIGH,
            detail = "Signer subject contains CN=Android Debug — this artifact was signed for development, indicating a repack or unreleased build.",
            evidence = emptyList(),
            remediation = "Release builds must be signed with the production keystore.",
        )
        if ("v1" in schemes && "v2" !in schemes) findings += Finding(
            id = "SIG-V1-ONLY",
            title = "Only the legacy JAR (v1) signature scheme",
            severity = Severity.MEDIUM,
            detail = "No APK Signature Scheme v2+ block found. v1-only artifacts are vulnerable to the Janus family of attacks (CVE-2017-13156) and strip-attacks.",
            evidence = emptyList(),
            remediation = "Sign with v2/v3 (default for modern build tooling).",
        )
        if (rotation) notes.add("Key rotation history present (v3 past signers)")
        if (certs.size > 1) notes.add("Multiple signers")

        val info = SigningInfo(
            signerSubject = first?.subjectX500Principal?.name,
            signerIssuer = first?.issuerX500Principal?.name,
            sha256Fingerprint = first?.encoded?.let {
                MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) }
            },
            debugCert = debugCert,
            multipleSigners = Build.VERSION.SDK_INT >= 28 && pi.signingInfo?.hasMultipleSigners() == true,
            rotationHistory = rotation,
            validFrom = first?.notBefore?.toString(),
            validTo = first?.notAfter?.toString(),
            sigAlgorithm = first?.sigAlgName,
            schemes = schemes,
            notes = notes,
        )
        return info to findings
    }

    /**
     * Detects which signing schemes are present. v1: JAR signature files
     * (SF/RSA/DSA) under META-INF. v2/v3/v3.1/stamp: parse the APK Signing
     * Block that sits between the last zip entry and the Central Directory
     * (presence detection, not crypto verification — that lands with apksig).
     */
    private fun detectSchemes(baseApkPath: String, zipNames: Set<String>): List<String> {
        val out = LinkedHashSet<String>()
        if (zipNames.any { it.startsWith("META-INF/") && (it.endsWith(".SF") || it.endsWith(".RSA") || it.endsWith(".DSA")) }) {
            out.add("v1")
        }
        runCatching {
            RandomAccessFile(baseApkPath, "r").use { raf ->
                val size = raf.length()
                if (size < 64) return@use
                val tail = ByteArray(minOf(65557L, size).toInt())
                raf.seek(size - tail.size)
                raf.readFully(tail)
                // find EOCD from the end
                var eocd = -1
                for (i in tail.size - 22 downTo 0) {
                    if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4b.toByte() &&
                        tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
                    ) { eocd = i; break }
                }
                if (eocd < 0) return@use
                val cdOff = leU32(tail, eocd + 16)
                if (cdOff <= 0 || cdOff >= size) return@use
                raf.seek(cdOff - 16)
                val magic = ByteArray(16)
                raf.readFully(magic)
                if (!magic.contentEquals("APK Sig Block 42".toByteArray(Charsets.US_ASCII))) return@use
                raf.seek(cdOff - 24)
                val blockSize = leU64(raf)
                // The stored size excludes its own 8-byte field, so the block
                // starts at cdOff - (size + 8), with the id/value pairs after it.
                val blockStart = cdOff - (blockSize + 8)
                if (blockSize <= 24 || blockStart < 0) return@use
                var pos = blockStart + 8
                while (pos + 12 <= cdOff - 24) {
                    raf.seek(pos)
                    val len = leU64(raf)
                    if (len <= 4 || len > cdOff - 24 - pos) break
                    val id = leU32Stream(raf)
                    when (id) {
                        0x7109871aL -> out.add("v2")
                        0xf05368c0L -> out.add("v3")
                        0x1b93ad61L -> out.add("v3.1")
                        0x2b09189eL -> out.add("source-stamp")
                        0x3ba06f8cL -> out.add("proof-of-rotation")
                    }
                    pos += 8 + len
                }
            }
        }
        return out.toList()
    }

    private fun leU32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
            ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24))

    private fun leU64(raf: RandomAccessFile): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((raf.read().toLong() and 0xFF) shl (8 * i))
        return v
    }

    private fun leU32Stream(raf: RandomAccessFile): Long {
        var v = 0L
        for (i in 0 until 4) v = v or ((raf.read().toLong() and 0xFF) shl (8 * i))
        return v
    }
}
