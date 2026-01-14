"""
Test the converter with the generated .spass file.
"""

from samsung_pass_to_bitwarden import BitwardenConverter
import json


def test_with_generated_file():
    converter = BitwardenConverter()
    export_data = converter.process_file("test_export.spass", "testpassword123")

    print("✓ Conversion successful!")
    print(f"  Total items: {len(export_data['items'])}")
    print()

    # Show summary by type
    type_names = {1: "Logins", 2: "Secure Notes", 3: "Cards", 4: "Identities"}
    type_counts = {}
    for item in export_data["items"]:
        t = item["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    for type_id, count in sorted(type_counts.items()):
        print(f"  {type_names.get(type_id, f'Type {type_id}')}: {count}")

    print()
    print("Output saved to: bitwarden_export.json")

    # Save output
    with open("bitwarden_export.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    # Show sample content
    print()
    print("Sample output:")
    print(json.dumps(export_data, indent=2)[:500] + "...")


if __name__ == "__main__":
    test_with_generated_file()
