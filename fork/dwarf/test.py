

class A:
    def __init__(self, b):
        self.b = b

class B:
    def __init__(self):
        self.a = None

    def setA(self, a):
        self.a = a

def main():
    b = B()
    a = A(b)
    b.setA(a)
    assert(a == b.a)
    assert(b == a.b)
    print(a)
    print(a.b)

    a.x = 5
    a.b.y = 5

    print(b.y)
    print(b.a.x)

if __name__ == "__main__":
    main()