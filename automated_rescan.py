"""
automated_rescan.py
Module for automated plugin version scanning via WordPress.org API.
Tracks previous scan results and reports new, resolved, or unchanged findings.
"""

import json
import os
import urllib.request
import urllib.error


class AutomatedRescan:
    """
    AutomatedRescan checks WordPress.org plugin versions against previous scan runs,
    reporting new, resolved, or unchanged findings.
    """

    STATE_FILENAME = "automated_rescan_state.json"

    def __init__(self, state_dir=None):
        if state_dir is None:
            state_dir = os.path.dirname(os.path.abspath(__file__))
        self.state_path = os.path.join(state_dir, self.STATE_FILENAME)
        self._state = {}
        self._load()

    def _load(self):
        """Load previous scan state from disk."""
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                self._state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._state = {}

    def _save(self):
        """Persist current scan state to disk."""
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)

    def check_updates(self, plugin_slug):
        """
        Fetch the latest version of a plugin from WordPress.org API
        and compare it with the previous scan result.

        Returns a dict with keys: plugin, previous_version, latest_version, status.
        Status is one of: "new", "update_available", "unchanged", "resolved".
        """
        # Fetch latest version from WordPress.org
        try:
            request = urllib.request.Request(
                f"https://api.wordpress.org/plugins/info/1.2/?action=query&request[slug]={plugin_slug}",
                headers={"User-Agent": "AutomatedRescan/1.0"}
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
            latest_version = data.get("version", "unknown")
        except Exception as e:
            latest_version = f"error: {e}"

        # Compare with previous scan
        previous_version = self._state.get(plugin_slug, {}).get("version")

        if previous_version is None:
            status = "new"
        elif latest_version == previous_version:
            status = "unchanged"
        else:
            # Version changed; if newer, "update_available", if older/unknown, "resolved"
            try:
                new_parts = tuple(map(int, latest_version.split(".")))
                old_parts = tuple(map(int, previous_version.split(".")))
                if new_parts > old_parts:
                    status = "update_available"
                else:
                    status = "resolved"
            except Exception:
                status = "update_available"

        # Update state
        self._state[plugin_slug] = {"version": latest_version}
        self._save()

        return {
            "plugin": plugin_slug,
            "previous_version": previous_version,
            "latest_version": latest_version,
            "status": status,
        }

    def rescan_previous(self):
        """
        Return a summary of previous scan findings for all tracked plugins.

        Returns a dict mapping plugin slugs to their previous scan data.
        """
        self._load()
        summary = {}
        for slug, data in self._state.items():
            summary[slug] = {
                "previous_version": data.get("version"),
                "scanned": True,
            }
        return summary

    def scan_plugins(self, plugin_slugs):
        """
        Convenience method to check updates for multiple plugins at once.

        Returns a list of result dicts from check_updates.
        """
        results = []
        for slug in plugin_slugs:
            results.append(self.check_updates(slug))
        return results