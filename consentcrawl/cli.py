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
        custom_prefs=custom_prefs
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
            urls.append(f"{parsed_url.scheme}://{parsed_url.hostname}")

    else:
        logging.error("No URL or valid .txt file with URLs to test")

    # Bootstrap blocklists
    blockers = blocklists.Blocklists(
        db_file=args.db_file,
        source_file=args.blocklists,
        force_bootstrap=args.bootstrap,
    )
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

    # Enforce correct pairing of flags
    if args.flow == "custom" and not parsed_categories:
        parser.error("--categories is required when --flow custom "
                     "(e.g., --categories 'analytics=off,advertising=off,functional=on')")
    if parsed_categories and args.flow != "custom":
        parser.error("--categories can only be used with --flow custom")

    results = asyncio.run(process_urls(
        urls=urls,
        batch_size=args.batch_size,
        tracking_domains_list=blockers.get_domains(),
        headless=args.headless,
        screenshot=args.screenshot,
        results_db_file=args.db_file,
        flow=args.flow,
        custom_prefs=parsed_categories,
    ))

    if args.show_output and len(results) < 25:
        sys.stdout.write(json.dumps(results, indent=2))

    sys.exit(0)

if __name__ == "__main__":
    cli()
