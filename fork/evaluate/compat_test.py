# creates a class object
def enum(**kwargs):
    pass
    # return type('Enum', (), {})

class Color(Enum):
    RED = auto()
    GREEN = auto()
    BLUE = auto()

def main():
    red = Color.RED
    print(type(red))
    print(red)

    blue = Color.BLUE
    print(type(blue))
    print(blue)

    print(red == blue)

if __name__ == "__main__":
    main()
