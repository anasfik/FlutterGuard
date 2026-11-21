package com.flutterguard.app.scan.rules

import com.flutterguard.app.scan.parsers.AxmlNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ManifestRulesTest {
    private fun manifestWithPermission(protectionLevel: String): AxmlNode {
        val manifest = AxmlNode("manifest")
        val application = AxmlNode("application")
        application.attrs["allowBackup"] = "false"
        manifest.children += application
        val permission = AxmlNode("permission")
        permission.attrs["name"] = "dev.flutterguard.benchmark.DANGEROUS"
        permission.attrs["protectionLevel"] = protectionLevel
        manifest.children += permission
        return manifest
    }

    private fun customPermissionIds(protectionLevel: String): List<String> =
        ManifestRules.evaluate(manifestWithPermission(protectionLevel), targetSdk = 36).first
            .map { it.id }

    @Test
    fun `literal dangerous protectionLevel is reported`() {
        assertTrue(
            "MAN-CUSTOMPERM must fire for a literal dangerous declaration",
            "MAN-CUSTOMPERM" in customPermissionIds("dangerous"),
        )
    }

    @Test
    fun `compiled protectionLevel 0x1 is reported`() {
        assertTrue(
            "MAN-CUSTOMPERM must fire for the compiled dangerous enum value 0x1",
            "MAN-CUSTOMPERM" in customPermissionIds("0x1"),
        )
    }

    @Test
    fun `compiled protectionLevel 1 is reported`() {
        assertTrue(
            "MAN-CUSTOMPERM must fire for the compiled dangerous enum value 1",
            "MAN-CUSTOMPERM" in customPermissionIds("1"),
        )
    }

    @Test
    fun `signature protectionLevel is not dangerous`() {
        val ids = customPermissionIds("0x2")
        assertEquals(
            "compiled signature protectionLevel must not be reported as dangerous",
            emptyList<String>(),
            ids.filter { it == "MAN-CUSTOMPERM" },
        )
    }
}
