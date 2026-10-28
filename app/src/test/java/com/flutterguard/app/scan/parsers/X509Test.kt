package com.flutterguard.app.scan.parsers

import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class X509Test {

    /** Real Ed25519 certificate embedded in Cake Wallet: subject CN=Omar Hatem, O=Cake Wallet. */
    private val cakeCert =
        "MIIBcTCCASOgAwIBAgIHPrm+8xIGEzAFBgMrZXAwEDEOMAwGA1UEAxMFQnJlZXowHhcNMjUxMjEyMTkzMDMyWhcN" +
            "MzUxMjEwMTkzMDMyWjArMRQwEgYDVQQKEwtDYWtlIFdhbGxldDETMBEGA1UEAxMKT21hciBIYXRlbTAqMAUGAytl" +
            "cAMhANCD9cvfIDwcoiDKKYdT9BunHLS2/OuKzV8NS0SzqV13o4GAMH4wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB" +
            "/wQCMAAwHQYDVR0OBBYEFNo5o+5ea0sNMlW/75VgGJCv2AcJMB8GA1UdIwQYMBaAFN6q1pJW843ndJIW/Ey2ILJr" +
            "KJhrMB4GA1UdEQQXMBWBE29tYXJAY2FrZXdhbGxldC5jb20wBQYDK2VwA0EAKgf7ua7656/pXJPBykpwAfkirrpP" +
            "6/Ue+9LXVm/qrS3PAIM2Onz4lThmYCQ2KeXhpQLVLZ9vW5v6M8JefAQHBQ"

    @Test
    fun readsSubjectDnNotIssuer() {
        val subject = X509.subject(cakeCert)
        assertTrue("subject was $subject", subject != null && subject.contains("CN=Omar Hatem"))
        assertTrue("subject was $subject", subject!!.contains("O=Cake Wallet"))
        // The issuer DN (CN=Breez) precedes the subject in the DER, so a
        // first-match lookup would have returned the wrong name.
        assertTrue("issuer leaked into subject: $subject", !subject.contains("Breez"))
    }

    @Test
    fun rejectsNonCertificateInput() {
        assertNull(X509.subject("not base64 at all"))
        assertNull(X509.subject("AAAA"))
    }
}
