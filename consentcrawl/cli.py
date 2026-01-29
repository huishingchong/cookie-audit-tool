import asyncio
import os
import json
import logging
import argparse
import sys
from consentcrawl import crawl, utils, blocklists
from urllib.parse import urlparse

async def process_urls(
    urls,
    batch_size,
    tracking_domains_list,
    headless=True,
    screenshot=True,
    results_db_file="crawl_results.db",
    flow="accept-all",
    custom_prefs=None,
    collect_domains=True,
    **kwargs,
):
    """
    Start the Playwright browser, run the URLs to test in batches asynchronously
    and write the data to a file.
    """

    return await crawl.crawl_batch(
        urls=urls,
        batch_size=batch_size,
        results_function=crawl.store_crawl_results,
        tracking_domains_list=tracking_domains_list,
        browser_config={"headless": headless, "channel": "chrome"},
        results_db_file=results_db_file,
        screenshot=screenshot,
        flow=flow,
        custom_prefs=custom_prefs,
        collect_domains=collect_domains,
        **kwargs,
    )


def cli():
    parser = argparse.ArgumentParser()

    parser.add_argument("url", help="URL or file with URLs to test")
    parser.add_argument(
        "--debug", default=False, action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--headless",
        default=True,
        type=utils.string_to_boolean,
        const=False,
        nargs="?",
        help="Run browser in headless mode (yes/no)",
    )
    parser.add_argument(
        "--screenshot",
        default=False,
        action="store_true",
        help="Take screenshots of each page before and after consent is given (if consent manager is detected)",
    )
    parser.add_argument(
        "--bootstrap",
        default=False,
        action="store_true",
        help="Force bootstrap (refresh) of blocklists",
    )
    parser.add_argument(
        "--batch_size",
        "-b",
        default=10,
        type=int,
        help="Number of URLs (and browser windows) to run in each batch. Default: 15, increase or decrease depending on your system capacity.",
    )
    parser.add_argument(
        "--show_output",
        "-o",
        default=False,
        action="store_true",
        help="Show output of the last results in terminal (max 25 results)",
    )
    parser.add_argument(
        "--db_file",
        "-db",
        default="crawl_results.db",
        help="Path to crawl results and blocklist database",
    )
    parser.add_argument(
        "--blocklists", "-bf", default=None, help="Path to custom blocklists file"
    )
    parser.add_argument(
        "--flow",
        default="accept-all",
        choices=["accept-all", "reject-all", "custom"],
        help="Consent path to run per URL (default: accept-all)",
    )
    parser.add_argument(
        "--categories",
        help="Only for --flow custom e.g. analytics=off,advertising=off,functional=on"
    )

    parser.add_argument(
    "--depth",
    type=int,
    default=1,
    help="Same-origin BFS depth for pre-consent exploration (default: 1).",
    )
    parser.add_argument(
        "--max_pages",
        type=int,
        default=12,
        help="Max number of same-origin pages to visit pre-consent (default: 12).",
    )
    parser.add_argument(
        "--clicks",
        type=int,
        default=6,
        help="Max non-destructive clicks per page pre-consent (default: 6).",
    )

    parser.add_argument(
        "--cookies_only",
        default=False,
        action="store_true",
        help="Only collect cookies (skip third-party/tracking domain analysis and skip blocklist loading)",
    )

    # parser.add_argument(
    #     "--auth",
    #     type=utils.string_to_boolean,
    #     default=False,
    #     help="Run crawler after authentication? (yes/no)",
    # )

    parser.add_argument(
        "--login-auto",
        action="store_true",
        default=False,
        help="Attempt to auto-discover a login/sign-in UI and authenticate before crawling.",
    )
    parser.add_argument(
        "--login-success-selector",
        default=None,
        help="CSS selector that is present only when logged in (e.g. account link).",
    )
    parser.add_argument(
        "--login-username-env",
        default=None,
        help="Env var name containing username for login (preferred).",
    )
    parser.add_argument(
        "--login-password-env",
        default=None,
        help="Env var name containing password for login (preferred).",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Username for login (use only for quick tests; prefer env).",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password for login (use only for quick tests; prefer env).",
    )
    parser.add_argument(
        "--login-storage-state",
        default=None,
        help="Path to save storage_state after successful login (optional).",
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if not args.db_file.endswith(".db"):
        args.db_file = args.db_file + ".db"

    if args.blocklists != None:
        if not os.path.isfile(args.blocklists):
            logging.error(f"Blocklists file not found: {args.blocklists}")
            sys.exit(1)

        if not any(
            [args.blocklists.endswith(".yaml"), args.blocklists.endswith(".yml")]
        ):
            logging.error(f"Blocklists file must be a YAML file: {args.blocklists}")
            sys.exit(1)

    if not os.path.isdir("screenshots") and args.screenshot == True:
        os.mkdir("screenshots")

    # List of URLs to test
    if args.url.endswith(".txt"):
        urls = []
        seen = set()
        with open(args.url, "r") as f:
            for line in f:
                s = line.strip().lower()
                if not s or s.startswith("#"):
                    continue
                if s not in seen:
                    seen.add(s)
                    urls.append(s)

    elif args.url != "":
        candidates = [u.strip() for u in args.url.split(",")]
        urls = []
        # Validate url syntax
        for u in candidates:
            if not u:
                continue
            if "://" not in u:
                u = "https://" + u
            parsed_url = urlparse(u)
            if not parsed_url.scheme in ("http", "https") or not parsed_url.hostname or "." not in parsed_url.hostname:
                logging.error(f"Invalid URL skipped: {u}")
                continue
            # urls.append(f"{parsed_url.scheme}://{parsed_url.hostname}")
            urls.append(parsed_url.geturl())

    else:
        logging.error("No URL or valid .txt file with URLs to test")

    if args.cookies_only:
        tracking_domains = []
    else:
        # Bootstrap blocklists
        blockers = blocklists.Blocklists(
            db_file=args.db_file,
            source_file=args.blocklists,
            force_bootstrap=args.bootstrap,
        )
        tracking_domains = blockers.get_domains()

    def _parse_categories(s):
        if not s:
            return None
        allowed = {"analytics", "functional", "advertising"}
        aliases = {
            "marketing": "advertising",
            "ads": "advertising",
            "advertisement": "advertising",
        }
        truthy = {"1", "true", "on", "yes"}
        falsy  = {"0", "false", "off", "no"}
        out = {}
        for raw in s.split(","):
            pair = raw.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise ValueError(f"Invalid pair '{pair}'. Use key=value.")
            k, v = pair.split("=", 1)
            key = aliases.get(k.strip().lower(), k.strip().lower())
            val = v.strip().lower()
            if key not in allowed:
                raise ValueError(f"Unknown category '{key}'. Allowed: {sorted(allowed)}")
            if val in truthy:
                out[key] = True
            elif val in falsy:
                out[key] = False
            else:
                raise ValueError(f"Invalid value '{val}' for {key}. Use on/off/true/false/yes/no/1/0")
        return out

    try:
        parsed_categories = _parse_categories(args.categories)
    except ValueError as e:
        parser.error(str(e))
    
    if args.flow == "custom" and not parsed_categories:
        parser.error("--categories is required when --flow custom "
                     "(e.g., --categories 'analytics=off,advertising=off,functional=on')")
    if parsed_categories and args.flow != "custom":
        parser.error("--categories can only be used with --flow custom")

    # Build optional login_flow dict (only if --login-auto)
    login_flow = None
    if args.login_auto:
        # Resolve credentials from environment first, then fall back to CLI values
        username = None
        password = None

        if args.login_username_env:
            username = os.environ.get(args.login_username_env)
        if args.login_password_env:
            password = os.environ.get(args.login_password_env)

        # Fallback to direct CLI flags if env vars are not set
        if not username:
            username = args.username
        if not password:
            password = args.password

        if not username or not password:
            logging.warning(
                "Login auto enabled but username/password are missing; "
                "login will likely fail (check --login-username-env/--login-password-env or --username/--password)."
            )

        login_flow = {
            # no login_url -> auto-discovery in crawler
            "success_selector": args.login_success_selector,
            "username": username,
            "password": password,
            "storage_state_path": args.login_storage_state,
        }

    results = asyncio.run(process_urls(
        urls=urls,
        # results_function=crawl.store_crawl_results,
        batch_size=args.batch_size,
        # tracking_domains_list=blockers.get_domains(),
        tracking_domains_list=tracking_domains,
        headless=args.headless,
        screenshot=args.screenshot,
        results_db_file=args.db_file,
        flow=args.flow,
        custom_prefs=parsed_categories,
        depth=args.depth,
        max_pages=args.max_pages,
        clicks=args.clicks,
        login_flow=login_flow,
        collect_domains=(not args.cookies_only),
    ))

    if args.show_output and len(results) < 25:
        sys.stdout.write(json.dumps(results, indent=2))

    sys.exit(0)

if __name__ == "__main__":
    cli()
