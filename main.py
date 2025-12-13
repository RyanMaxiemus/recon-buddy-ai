import sys

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        print("❌ Error: I need a target, boss. Pass an IP.")
        return

    print(f"🕵️  Starting recon on {target}...")
    # TODO: result = scanner.run_nmap(target)
    # TODO: ai_summary = ai_parser.analyze(result)
    
if __name__ == "__main__":
    main()