import io
import unittest
from contextlib import redirect_stdout
from unittest import mock
from urllib.parse import parse_qs, urlparse

import scanner


class PluginDiscoveryTests(unittest.TestCase):
    def test_search_uses_wordpress_search_parameter_instead_of_browse(self):
        url = scanner.api_url(
            scanner.plugin_query_params("popular", 2, 50, "image optimization")
        )
        query = parse_qs(urlparse(url).query)

        self.assertEqual(query["request[search]"], ["image optimization"])
        self.assertEqual(query["request[page]"], ["2"])
        self.assertNotIn("request[browse]", query)

    def test_feed_query_uses_selected_browse_value(self):
        query = scanner.plugin_query_params("top-rated", 1, 100)

        self.assertEqual(query["request[browse]"], "top-rated")
        self.assertNotIn("request[search]", query)

    def test_interactive_search_returns_keyword_without_feed_fallback(self):
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=["7", " image optimizer "]), \
                redirect_stdout(output):
            selection = scanner.choose_discovery_feed()

        self.assertEqual(selection, ("updated", "image optimizer"))
        self.assertIn("Recently updated", output.getvalue())
        self.assertIn("Search WordPress.org by keyword", output.getvalue())

    def test_interactive_default_is_recently_updated(self):
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(scanner.choose_discovery_feed(), ("updated", None))


if __name__ == "__main__":
    unittest.main()
