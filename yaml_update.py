from ruamel.yaml import YAML
import sys

def update_values_section(yaml_file, updates):
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 999999  # Prevent line breaks

    with open(yaml_file, 'r') as f:
        data = yaml.load(f)

    values = data.get('spec', {}).get('values', {})
    if not isinstance(values, dict):
        print(f"[!] 'spec.values' not found or not a dictionary in {yaml_file}")
        sys.exit(1)

    for field, new_value in updates.items():
        field_entry = values.get(field, {})

        if 'valuePlaintext' in field_entry:
            field_entry['valuePlaintext'] = new_value
        elif 'value' in field_entry:
            field_entry['value'] = new_value
        else:
            # Default to valuePlaintext if neither exists
            field_entry['valuePlaintext'] = new_value

        values[field] = field_entry

    with open(yaml_file, 'w') as f:
        yaml.dump(data, f)

    print(f"[✓] Updated fields in {yaml_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python update_mixed_fields.py <yaml_file> field1=value1 field2=value2 ...")
        sys.exit(1)

    yaml_file = sys.argv[1]
    update_pairs = dict(arg.split("=", 1) for arg in sys.argv[2:])
    update_values_section(yaml_file, update_pairs)
