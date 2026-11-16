<?php
$wpdb->query("SELECT " . $_GET["query"]);
echo $_POST["content"];
