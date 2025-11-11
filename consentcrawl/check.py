def count_records(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            print(f"Number of records in the file: {len(lines)}")
    except FileNotFoundError:
        print("Error: File not found. Please check the file path.")
    except Exception as e:
        print(f"An error occurred: {e}")

file_path = "~/cookie-audit-tool/frasers.txt"
count_records(file_path)


# TEST RUNS
# python3 -m consentcrawl.cli "https://www.18montrose.com" --flow accept-all --debug --db custom.db
# python3 -m consentcrawl.cli "https://www.18montrose.com" --flow reject-all --debug --db custom.db
# python3 -m consentcrawl.cli "https://www.18montrose.com" --flow custom --categories "analytics=off,functional=off,advertising=off" --debug --db custom.db

# python3 consentcrawl/output.py ~/cookie-audit-tool/custom.db --out custom.txt


# Run individually
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_000 --flow custom -c analytics=0,functional=0,advertising=0
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_001 --flow custom -c analytics=0,functional=0,advertising=1
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_010 --flow custom -c analytics=0,functional=1,advertising=0
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_011 --flow custom -c analytics=0,functional=1,advertising=1
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_100 --flow custom -c analytics=1,functional=0,advertising=0
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_101 --flow custom -c analytics=1,functional=0,advertising=1
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_110 --flow custom -c analytics=1,functional=1,advertising=0
# python3 -m consentcrawl ~/Desktop/frasers.txt --batch_size 1 --debug -o --db_file frasers_111 --flow custom -c analytics=1,functional=1,advertising=1

# python -m consentcrawl.cli ~/Desktop/frasers.txt --flow custom --categories "analytics=off,advertising=off,functional=on" --batch_size 5 --db_file frasers

# Cookie classification + rules
"""
python -m consentcrawl.classification \
  --db crawl_results.db \
  --rules consentcrawl/assets/cookie_rules.yml \
  --ocd open-cookie-database.csv \
  --out ./reports \
  --reset
"""

# SQLite
# sqlite3 name.db
# .headers on
# .mode column
# SELECT name FROM sqlite_master WHERE type='table';
# DROP TABLE IF EXISTS table_name;
# .quit

# TO DO:
# - Fix batch crawling - deterministic timing and results?
# - check parse_expiry logic
# - Automatically all flows: New TXT file per custom or flow (output.py)?
# - Interact with website more to get potentially more cookies?
# - Combine similar actions
# - Create dashboard - customise rules somehow - let user select


# Challenge cases:
# python -m consentcrawl.cli https://www.houseoffraser.co.uk/,https://sg.sportsdirect.com,https://us.sportsdirect.com,https://www.studio.co.uk --flow accept-all --batch_size 1 --db_file outputdb

'''
python3 -m consentcrawl \
  --db_file database.db \
  --flow accept-all \
  --urls frasers.txt \
  --depth 1 \
  --max_pages 12 \
  --clicks 6
'''

'''
python3 -m consentcrawl \
  --db_file check.db \
  --flow accept-all \
  --urls https://www.houseoffraser.co.uk/,https://sg.sportsdirect.com,https://us.sportsdirect.com,https://www.studio.co.uk  \
  --depth 3 \
  --max_pages 20 \
  --clicks 20
'''

'''
python3 -m consentcrawl   https://www.houseoffraser.co.uk \
  --db_file hof.db \
  --flow accept-all \
  --max_pages 20 \
  --depth 3 \
  --clicks 20
'''