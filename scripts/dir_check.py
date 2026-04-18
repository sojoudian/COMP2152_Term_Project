import urllib.request

def check_directory(url):
    try:
        print(f"Checking {url}...\n")

        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode()

        if "Index of /" in content:
            print("VULNERABILITY FOUND:")
            print("Directory listing is enabled.\n")

        if ".env" in content or "config.php" in content:
            print("Sensitive files exposed in directory.\n")

    except Exception as e:
        print(f"Error: {e}")

def main():
    target = "http://files.0x10.cloud"
    check_directory(target)

if __name__ == "__main__":
    main()