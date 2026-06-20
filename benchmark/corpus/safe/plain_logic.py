def total(items):
    return sum(i.price * i.qty for i in items)

def format_name(first, last):
    return f"{first} {last}".strip().title()

class Cart:
    def __init__(self):
        self.items = []
    def add(self, item):
        self.items.append(item)
