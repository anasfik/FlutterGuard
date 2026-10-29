package com.flutterguard.app.scan

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * N6: only a file that declares *this* schema version is a FlutterGuard report.
 * Backing fields are no longer invented for a schema-less or future file.
 * (`decode` itself needs `org.json`, which is stubbed on the JVM: the acceptance
 * predicate below is the part that can run here, and `decode` uses it.)
 */
class ReportJsonTest {

    @Test
    fun onlyTheKnownSchemaIsAccepted() {
        assertTrue(ReportJson.acceptsSchema(ReportJson.SCHEMA))
        assertFalse("a missing schema must not default to a report", ReportJson.acceptsSchema(null))
        assertFalse(ReportJson.acceptsSchema(""))
        assertFalse("a future schema must not be decoded with today's defaults", ReportJson.acceptsSchema("flutterguard/report/2"))
        assertFalse(ReportJson.acceptsSchema("{\"a\":1}"))
    }
}
