import pickle
import inspect

def view_pkl_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = pickle.load(file)
            print("Contents of the pickle file:")
            
            # Print the type of the loaded object
            print("Type of the loaded object:", type(data))
            
            # Print all attributes and methods of the object
            print("\nAttributes and methods of the loaded object:")
            for attr in dir(data):
                if not attr.startswith("__"):
                    try:
                        attr_value = getattr(data, attr)
                        if callable(attr_value):
                            print(f"\n{attr} (callable):")
                            print(f"Signature: {inspect.signature(attr_value)}")
                            print(f"Docstring: {inspect.getdoc(attr_value)}")
                        else:
                            print(f"\n{attr}: {attr_value}")
                    except Exception as e:
                        print(f"Error accessing attribute {attr}: {e}")
            
            # If the object has specific attributes such as layers, weights, etc.
            if hasattr(data, 'summary'):
                print("\nModel Summary:")
                data.summary()

            if hasattr(data, 'get_config'):
                print("\nModel Configuration:")
                print(data.get_config())
            
            if hasattr(data, 'get_weights'):
                print("\nModel Weights:")
                weights = data.get_weights()
                for i, weight in enumerate(weights):
                    print(f"Weight {i}: {weight.shape}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="View the contents of a pickle (.pkl) file.")
    parser.add_argument("file_path", help="Path to the pickle file")

    args = parser.parse_args()

    view_pkl_file(args.file_path)
