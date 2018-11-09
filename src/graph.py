import matplotlib.pyplot as plt
import pandas as pd

def main():
    df = pd.read_csv('cipher.csv')
    plt.plot(df['char'].tolist(), df['enc'].tolist())
    plt.plot(df['char'].tolist(), df['dec'].tolist())
    plt.legend(["Encryption", "Decryption"])
    plt.title("Charecter vs Time")
    plt.xlabel('Charecter')
    plt.ylabel('Time')
    plt.show()

if __name__ == '__main__':
    main()