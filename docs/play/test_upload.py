"""Offline release-safety checks: python3 docs/play/test_upload.py."""
import contextlib
import io
import unittest
import urllib.parse
from unittest.mock import patch

import upload


class ReleaseSafetyTest(unittest.TestCase):
    def test_commit_protects_pending_review_and_keeps_failed_edit(self):
        with patch.object(upload, "token", return_value="unused"):
            play = upload.Play("unused", "com.flutterguard.app")
        for rejected in (False, True):
            with self.subTest(rejected=rejected):
                play.edit = "edit-123"
                with patch.object(play, "call", return_value={}) as call:
                    if rejected:
                        call.side_effect = SystemExit("CHANGES_ALREADY_IN_REVIEW")
                        with self.assertRaisesRegex(SystemExit, "CHANGES_ALREADY_IN_REVIEW"):
                            play.commit()
                    else:
                        play.commit()
                self.assertEqual(call.call_count, 1)  # Never retry without the guard.
                method, url = call.call_args.args
                self.assertEqual(method, "POST")
                self.assertEqual(urllib.parse.urlsplit(url).path,
                                 "/androidpublisher/v3/applications/com.flutterguard.app/edits/edit-123:commit")
                self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query),
                                 {"changesInReviewBehavior": ["ERROR_IF_IN_REVIEW"]})
                self.assertEqual(play.edit, "edit-123" if rejected else None)

    def test_status_distinguishes_rollout_from_review_without_committing(self):
        with patch.object(upload, "token", return_value="unused"):
            play = upload.Play("unused", "com.flutterguard.app")
        base = upload.API + "/applications/com.flutterguard.app"
        responses = {
            ("POST", base + "/edits"): {"id": "status-edit"},
            ("GET", base + "/edits/status-edit/bundles"): {"bundles": []},
            ("GET", base + "/edits/status-edit/tracks"): {"tracks": [
                {"track": "production", "releases": [{"versionCodes": ["7"], "status": "completed"}]},
                {"track": "beta", "releases": []},
            ]},
            ("GET", base + "/tracks/production/releases"): {"releases": [
                {"releaseName": "0.3.2", "activeArtifacts": [{"versionCode": 7}],
                 "releaseLifecycleState": "RELEASE_LIFECYCLE_STATE_IN_REVIEW", "track": "production"},
            ]},
            ("GET", base + "/edits/status-edit/listings/en-US"): {"title": "FlutterGuard"},
            ("DELETE", base + "/edits/status-edit"): {},
        }
        for kind in ("icon", "featureGraphic", "phoneScreenshots"):
            responses[("GET", base + "/edits/status-edit/listings/en-US/" + kind)] = {"images": []}
        output = io.StringIO()
        with patch.object(play, "call", side_effect=lambda method, url: responses[(method, url)]) as call:
            with contextlib.redirect_stdout(output):
                play.status()
        self.assertIn("['7'] completed", output.getvalue())
        self.assertIn("IN_REVIEW", output.getvalue())
        self.assertIn("[7]", output.getvalue())
        self.assertIn("beta: no releases", output.getvalue())
        self.assertEqual(call.call_count, len(responses))
        self.assertIsNone(play.edit)


if __name__ == "__main__":
    unittest.main()
