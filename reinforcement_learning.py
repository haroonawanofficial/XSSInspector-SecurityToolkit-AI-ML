class ReinforcementLearningAgent:
    def __init__(self):
        self.history = []

    def learn(self, url, param, payload, method, success):
        self.history.append((url, param, payload, method, success))
        # Implement your learning algorithm here

    def select_payload(self, url, param):
        # Implement your payload selection algorithm here
        return '<script>alert("XSS")</script>'
