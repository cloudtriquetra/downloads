# sample.py

import argparse

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="Process some user inputs.")

    # Add arguments
    parser.add_argument('-n', '--name', type=str, required=True, help='Your name')
    parser.add_argument('-a', '--age', type=int, required=True, help='Your age')
    parser.add_argument('-c', '--color', type=str, required=True, help='Your favorite color')

    # Parse the arguments
    args = parser.parse_args()

    # Print the collected inputs
    print(f"Hello, {args.name}!")
    print(f"You are {args.age} years old.")
    print(f"Your favorite color is {args.color}.")

if __name__ == "__main__":
    main()
