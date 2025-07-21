from ruamel.yaml import YAML
import sys

def update_deep_fields(yaml_file, updates):
    yaml = YAML()
    yaml.preserve_quotes = True

    with open(yaml_file, 'r') as f:
        data = yaml.load(f)

    # Navigate safely
    values = data.get('spec', {}).get('values', {})
    if not isinstance(values, dict):
        print(f"[!] 'spec.values' not found or not a dictionary in {yaml_file}")
        sys.exit(1)

    for field, new_value in updates.items():
        if field not in values:
            values[field] = {}
        values[field]['value'] = new_value

    with open(yaml_file, 'w') as f:
        yaml.dump(data, f)

    print(f"[✓] Updated spec.values.<field>.value in {yaml_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python update_deep_fields.py <yaml_file> field1=value1 field2=value2 ...")
        sys.exit(1)

    yaml_file = sys.argv[1]
    update_pairs = dict(arg.split("=", 1) for arg in sys.argv[2:])
    update_deep_fields(yaml_file, update_pairs)
