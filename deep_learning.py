import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input

class DeepLearningModel:
    def __init__(self):
        self.model = self.build_model()

    def build_model(self):
        model = Sequential()
        model.add(Input(shape=(2,)))  # Adjust input shape to match features
        model.add(Dense(64, activation='relu'))
        model.add(Dense(32, activation='relu'))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        return model

    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(np.array(X), np.array(y), test_size=0.3)
        self.model.fit(X_train, y_train, epochs=10, batch_size=10, verbose=1)
        predictions = (self.model.predict(X_test) > 0.5).astype("int32")
        accuracy = accuracy_score(y_test, predictions)
        print(f"Model trained with accuracy: {accuracy:.2f}")

    def predict(self, X):
        return (self.model.predict(np.array(X)) > 0.5).astype("int32")
