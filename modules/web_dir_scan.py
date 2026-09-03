from utils import validation, runner, formatter
import os
import urllib.request
import urllib.error

COMMON_DIRS = [
    # Admin & Login
    "admin",
    "administrator",
    "login",
    "admin.php",
    "admin.html",
    "dashboard",
    "cpanel",
    "user",
    "users",
    "account",
    # Sensitive Files & Configs
    ".git",
    ".env",
    ".htaccess",
    ".htpasswd",
    "config",
    "config.php",
    "config.json",
    "settings.py",
    "wp-config.php",
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    "server-status",
    # Databases & Backups
    "db",
    "database",
    "backup",
    "backups",
    "backup.sql",
    "db.sql",
    "dump.sql",
    "old",
    "temp",
    # APIs & Endpoints
    "api",
    "api/v1",
    "swagger",
    "graphql",
    # Uploads & Media
    "uploads",
    "images",
    "files",
    "media",
    "static",
    # Common Tools & CMS Paths
    "phpmyadmin",
    "wp-admin",
    "wp-content",
    "test",
    "staging",
    "dev"
]


def check_dir(base_url: str, path: str) -> tuple[str, int | None]:
    url = f"{base_url}/{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return path, response.status
    except urllib.error.HTTPError as e: 
        return path, e.code
    except (urllib.error.URLError, TimeoutError, Exception):
        return path, None

def run():
    target = input("Enter target domain or URL: ").strip()

    
    
    